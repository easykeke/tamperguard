package audit

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// OpenFile opens path for appending and resumes the chain from the last record
// already stored there.
//
// Fail-closed rule: if the file exists but its tail is not a valid record, this
// returns an error instead of silently starting a fresh chain. Silently
// resetting seq would turn an attacker's "truncate the log" into a clean
// restart that the server cannot distinguish from a first boot.
func OpenFile(path, agentID string, priv ed25519.PrivateKey) (*Writer, *os.File, error) {
	nextSeq, prevHash, err := resumePoint(path)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return NewWriter(agentID, priv, f, nextSeq, prevHash), f, nil
}

func resumePoint(path string) (uint64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 1, "", nil
		}
		return 0, "", err
	}
	defer f.Close()

	var last string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) > 0 {
			last = string(line)
		}
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return 0, "", fmt.Errorf("audit: scan %s: %w", path, err)
	}
	if last == "" {
		return 1, "", nil
	}
	var r Record
	if err := json.Unmarshal([]byte(last), &r); err != nil {
		return 0, "", fmt.Errorf("audit: tail of %s is corrupt (%v); refusing to resume the chain", path, err)
	}
	if r.Hash == "" || r.Seq == 0 {
		return 0, "", fmt.Errorf("audit: tail of %s has no hash/seq; refusing to resume", path)
	}
	return r.Seq + 1, r.Hash, nil
}
