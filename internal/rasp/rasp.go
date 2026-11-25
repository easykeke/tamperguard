// Package rasp implements the application-layer probe channel.
//
// The kernel layer decides by process identity, so a write performed by a
// legitimate web process is allowed. A compromised web application can abuse
// exactly that: the process is legitimate, the write is not. The RASP probe runs
// inside the application runtime, sees the call site and the target path before
// the write happens, and asks the local agent what to do.
//
// Protocol (newline delimited JSON over a Unix socket, mode 0600):
//
//	client -> {"type":"hello","pid":123,"app":"node"}
//	server -> {"type":"config","rules":[{"path":"/var/www","recursive":true,"mode":"enforce"}]}
//	client -> {"type":"event","path":"/var/www/x.php","op":"write","decision":"blocked","pid":123,"stack":"..."}
//
// Rules are pushed again whenever the policy changes, so an administrator can
// move a path from observe to enforce without restarting the application.
package rasp

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Rule mirrors the policy rule the probe must apply.
type Rule struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
	Mode      string `json:"mode"`
}

// Event is one decision reported by a probe.
type Event struct {
	Path     string
	Op       string
	Decision string // allowed | observed | blocked
	PID      int
	App      string
	Stack    string
}

// Message is the wire format in both directions.
type Message struct {
	Type     string `json:"type"`
	PID      int    `json:"pid,omitempty"`
	App      string `json:"app,omitempty"`
	Rules    []Rule `json:"rules,omitempty"`
	Path     string `json:"path,omitempty"`
	Op       string `json:"op,omitempty"`
	Decision string `json:"decision,omitempty"`
	Stack    string `json:"stack,omitempty"`
}

type connState struct {
	mu   sync.Mutex
	enc  *json.Encoder
	conn net.Conn
}

// Server accepts probe connections and fans policy updates out to them.
type Server struct {
	socket  string
	log     *slog.Logger
	onEvent func(Event)

	mu    sync.Mutex
	rules []Rule
	conns map[*connState]struct{}
	ln    net.Listener
	done  chan struct{}
	once  sync.Once
}

// New starts listening on socketPath. The socket is removed and recreated so a
// stale file from a crashed agent does not block startup.
func New(socketPath string, onEvent func(Event), logger *slog.Logger) (*Server, error) {
	if socketPath == "" {
		return nil, errors.New("rasp: socket path is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return nil, err
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	s := &Server{
		socket:  socketPath,
		log:     logger,
		onEvent: onEvent,
		conns:   map[*connState]struct{}{},
		ln:      ln,
		done:    make(chan struct{}),
	}
	go s.acceptLoop()
	return s, nil
}

// Socket returns the socket path (for diagnostics).
func (s *Server) Socket() string { return s.socket }

// Clients returns how many probes are connected.
func (s *Server) Clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// UpdateRules stores the rules and pushes them to every connected probe.
func (s *Server) UpdateRules(rules []Rule) {
	s.mu.Lock()
	s.rules = rules
	conns := make([]*connState, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		s.send(c, Message{Type: "config", Rules: rules})
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				s.log.Warn("rasp: accept failed", "err", err)
				return
			}
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	st := &connState{conn: conn, enc: json.NewEncoder(conn)}
	defer func() {
		s.mu.Lock()
		delete(s.conns, st)
		s.mu.Unlock()
		conn.Close()
	}()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		switch m.Type {
		case "hello":
			s.mu.Lock()
			s.conns[st] = struct{}{}
			rules := s.rules
			s.mu.Unlock()
			s.log.Info("rasp probe connected", "pid", m.PID, "app", m.App, "clients", s.Clients())
			s.send(st, Message{Type: "config", Rules: rules})
		case "event":
			if s.onEvent != nil {
				s.onEvent(Event{
					Path: m.Path, Op: m.Op, Decision: m.Decision,
					PID: m.PID, App: m.App, Stack: m.Stack,
				})
			}
		}
	}
}

func (s *Server) send(st *connState, m Message) {
	st.mu.Lock()
	defer st.mu.Unlock()
	_ = st.enc.Encode(m)
}

// Close stops accepting and closes every probe connection.
func (s *Server) Close() error {
	s.once.Do(func() {
		close(s.done)
		_ = s.ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			_ = c.conn.Close()
		}
		s.conns = map[*connState]struct{}{}
		s.mu.Unlock()
		_ = os.Remove(s.socket)
	})
	return nil
}
