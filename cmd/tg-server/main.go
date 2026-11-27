// Command tg-server is the TamperGuard control plane.
//
// Subcommands:
//
//	tg-server init            generate CA, keys, admin password, bootstrap tokens
//	tg-server serve           run the control plane
//	tg-server bootstrap-token issue another one-time enrolment token
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/idgen"
	"github.com/easykeke/tamperguard/internal/release"
	"github.com/easykeke/tamperguard/internal/server"
	"github.com/easykeke/tamperguard/internal/store"
	"github.com/easykeke/tamperguard/internal/token"
	webui "github.com/easykeke/tamperguard/web"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "serve":
		if handled, serr := tryServerService("TamperGuardServer", os.Args[2:]); handled {
			err = serr
			break
		}
		err = cmdServe(os.Args[2:])
	case "bootstrap-token":
		err = cmdBootstrapToken(os.Args[2:])
	case "reset-admin-password":
		err = cmdResetPassword(os.Args[2:])
	case "release":
		err = cmdRelease(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `TamperGuard control plane

  tg-server init [--data-dir DIR] [--listen ADDR]
  tg-server serve [--data-dir DIR]
  tg-server bootstrap-token [--data-dir DIR] [--role protect|publish]
  tg-server release --data-dir DIR --binary PATH --version V [--os linux] [--arch amd64]
  tg-server reset-admin-password [--data-dir DIR] [--password NEW]
`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dataDir := fs.String("data-dir", config.DefaultServerDir, "data directory")
	listen := fs.String("listen", config.DefaultListenAddr, "listen address")
	_ = fs.Parse(args)

	if err := os.MkdirAll(filepath.Join(*dataDir, config.KeysDir), 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(*dataDir, config.ServerConfigFile)); err == nil {
		return fmt.Errorf("%s already initialised (remove it to re-initialise)", *dataDir)
	}

	// CA and server certificate use ECDSA P-256: Ed25519 certificates are
	// rejected by Windows Schannel and some other TLS stacks, which breaks the
	// admin console for those clients. Signing keys (tokens, policy, releases)
	// stay Ed25519.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caCert, caDER, err := makeCA(caKey)
	if err != nil {
		return err
	}
	if err := config.WriteCertPEM(filepath.Join(*dataDir, config.KeysDir, config.CACertFile), caDER); err != nil {
		return err
	}
	if err := config.WritePrivateKey(filepath.Join(*dataDir, config.KeysDir, config.CAKeyFile), caKey); err != nil {
		return err
	}

	// Server TLS certificate signed by the CA.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serverDER, err := makeServerCert(&serverKey.PublicKey, caCert, caKey)
	if err != nil {
		return err
	}
	if err := config.WriteCertPEM(filepath.Join(*dataDir, config.KeysDir, config.ServerCertFile), serverDER); err != nil {
		return err
	}
	if err := config.WritePrivateKey(filepath.Join(*dataDir, config.KeysDir, config.ServerKeyFile), serverKey); err != nil {
		return err
	}

	// Token and policy signing keys.
	tokenPriv, err := genKeyFile(filepath.Join(*dataDir, config.KeysDir, config.TokenSignFile),
		filepath.Join(*dataDir, config.KeysDir, config.IssuerPubFile))
	if err != nil {
		return err
	}
	policyPriv, err := genKeyFile(filepath.Join(*dataDir, config.KeysDir, config.PolicySignFile),
		filepath.Join(*dataDir, config.KeysDir, config.PolicyPubFile))
	if err != nil {
		return err
	}
	releasePriv, err := genKeyFile(filepath.Join(*dataDir, config.KeysDir, config.ReleaseSignFile),
		filepath.Join(*dataDir, config.KeysDir, config.ReleasePubFile))
	if err != nil {
		return err
	}
	_ = tokenPriv
	_ = policyPriv
	_ = releasePriv

	// Session key and admin password.
	sessKey := make([]byte, 32)
	if _, err := rand.Read(sessKey); err != nil {
		return err
	}
	adminPassword := randomPassword(24)
	pwHash, err := server.HashPassword(adminPassword)
	if err != nil {
		return err
	}

	cfg := config.DefaultServer(*dataDir)
	cfg.ListenAddr = *listen
	cfg.SessionKey = base64.StdEncoding.EncodeToString(sessKey)
	cfg.AdminPasswordHash = pwHash
	if err := config.SaveServer(cfg); err != nil {
		return err
	}

	// Create the database and one bootstrap token per role.
	st, err := store.Open(filepath.Join(*dataDir, "tamperguard.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	protectTok := idgen.Token(24)
	publishTok := idgen.Token(24)
	if err := st.AddBootstrapToken(token.DigestString(protectTok), "protect"); err != nil {
		return err
	}
	if err := st.AddBootstrapToken(token.DigestString(publishTok), "publish"); err != nil {
		return err
	}

	fmt.Printf(`
TamperGuard initialised in %s

  Admin user      : %s
  Admin password  : %s
  Bootstrap token (protect) : %s
  Bootstrap token (publish) : %s

The password and tokens are printed exactly once. Store them now.
Start the server with: tg-server serve --data-dir %s
`, *dataDir, cfg.AdminUser, adminPassword, protectTok, publishTok, *dataDir)
	return nil
}

func cmdServe(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cmdServeContext(args, ctx)
}

func cmdServeContext(args []string, ctx context.Context) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data-dir", config.DefaultServerDir, "data directory")
	_ = fs.Parse(args)

	var logOut io.Writer = os.Stderr
	logPath := filepath.Join(*dataDir, "server.log")
	if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		defer f.Close()
		logOut = io.MultiWriter(os.Stderr, f)
	}
	logger := slog.New(slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.LoadServer(*dataDir)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(*dataDir, "tamperguard.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	srv, err := server.New(cfg, st, server.Options{Logger: logger, UI: webui.FS()})
	if err != nil {
		return err
	}
	return srv.Serve(ctx)
}

func cmdBootstrapToken(args []string) error {
	fs := flag.NewFlagSet("bootstrap-token", flag.ExitOnError)
	dataDir := fs.String("data-dir", config.DefaultServerDir, "data directory")
	role := fs.String("role", "protect", "protect or publish")
	_ = fs.Parse(args)
	if *role != "protect" && *role != "publish" {
		return fmt.Errorf("role must be protect or publish")
	}
	if _, err := config.LoadServer(*dataDir); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(*dataDir, "tamperguard.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	tok := idgen.Token(24)
	if err := st.AddBootstrapToken(token.DigestString(tok), *role); err != nil {
		return err
	}
	fmt.Printf("bootstrap token (%s role, valid for one use): %s\n", *role, tok)
	return nil
}

// cmdResetPassword resets the administrator password from the host (break-glass
// path when the console password is lost). A random password is generated and
// printed when --password is omitted.
func cmdResetPassword(args []string) error {
	fs := flag.NewFlagSet("reset-admin-password", flag.ExitOnError)
	dataDir := fs.String("data-dir", config.DefaultServerDir, "data directory")
	password := fs.String("password", "", "new password (empty generates a random one)")
	_ = fs.Parse(args)
	cfg, err := config.LoadServer(*dataDir)
	if err != nil {
		return err
	}
	pw := *password
	if pw == "" {
		pw = idgen.Token(9)
	}
	if len(pw) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := server.HashPassword(pw)
	if err != nil {
		return err
	}
	cfg.AdminPasswordHash = hash
	if err := config.SaveServer(cfg); err != nil {
		return err
	}
	fmt.Printf("admin password reset\n  user:     %s\n  password: %s\n", cfg.AdminUser, pw)
	return nil
}

// cmdRelease publishes an agent binary for self-upgrade: it copies the file
// into the release store, records its hash, and prints the signed manifest.
func cmdRelease(args []string) error {
	fs := flag.NewFlagSet("release", flag.ExitOnError)
	dataDir := fs.String("data-dir", config.DefaultServerDir, "data directory")
	binary := fs.String("binary", "", "agent binary to publish")
	version := fs.String("version", "", "version string, e.g. 0.2.0")
	osName := fs.String("os", "linux", "target OS")
	arch := fs.String("arch", "amd64", "target architecture")
	_ = fs.Parse(args)
	if *binary == "" || *version == "" {
		return fmt.Errorf("--binary and --version are required")
	}

	cfg, err := config.LoadServer(*dataDir)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(*dataDir, "tamperguard.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	data, err := os.ReadFile(*binary)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	manifest := release.Manifest{
		Version: *version,
		OS:      *osName,
		Arch:    *arch,
		SHA256:  hex.EncodeToString(sum[:]),
		Size:    int64(len(data)),
	}
	priv, err := config.ReadEd25519Private(cfg.KeyPath(config.ReleaseSignFile))
	if err != nil {
		return fmt.Errorf("release signing key: %w", err)
	}
	if err := manifest.Sign(priv); err != nil {
		return err
	}

	destDir := filepath.Join(*dataDir, "releases", *version)
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return err
	}
	dest := filepath.Join(destDir, "tg-agent-"+*osName+"-"+*arch)
	if err := config.WriteFileAtomic(dest, data, 0o755); err != nil {
		return err
	}
	if err := st.UpsertRelease(store.Release{
		Version: *version, OS: *osName, Arch: *arch,
		SHA256: manifest.SHA256, Size: manifest.Size, PublishedAt: time.Now().Unix(),
	}); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(manifest, "", "  ")
	fmt.Printf("published %s/%s %s (%d bytes, sha256 %s)\n%s\n", *osName, *arch, *version, manifest.Size, manifest.SHA256, raw)
	return nil
}

// ---------- key and certificate helpers ----------

func genKeyFile(privPath, pubPath string) (ed25519.PrivateKey, error) {
	pub, priv, err := token.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := config.WriteEd25519Private(privPath, priv); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return priv, config.WriteFileAtomic(pubPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
}

func makeCA(caKey *ecdsa.PrivateKey) (*x509.Certificate, []byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "TamperGuard CA", Organization: []string{"TamperGuard"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, der, err
}

func makeServerCert(pub *ecdsa.PublicKey, ca *x509.Certificate, caKey crypto.Signer) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tg-server", Organization: []string{"TamperGuard"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", host, "tg-server"},
		IPAddresses:           serverCertIPs(),
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
}

func randomPassword(n int) string {
	const charset = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	for i := range out {
		out[i] = charset[int(buf[i])%len(charset)]
	}
	return string(out)
}

// serverCertIPs includes loopback plus every local unicast address, so agents
// can connect with https://<ip>:8443 in addition to the hostname.
func serverCertIPs() []net.IP {
	out := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}
