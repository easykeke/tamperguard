package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/easykeke/tamperguard/internal/tpmquote"
)

// maybeAttest answers a pending TPM challenge. It is a no-op unless the agent
// was configured with an AK context and the server issued a nonce.
func (a *Agent) maybeAttest(ctx context.Context) {
	if a.opts.TPMQuoteAK == "" {
		return
	}
	a.attestMu.Lock()
	nonce := a.attestNonce
	a.attestMu.Unlock()
	if nonce == "" {
		return
	}
	ev, err := a.runTPMQuote(ctx, nonce)
	if err != nil {
		a.log.Warn("TPM quote failed", "err", err)
		return
	}
	if err := a.client.UploadAttestation(ctx, nonce, ev); err != nil {
		a.log.Warn("TPM quote upload failed", "err", err)
		return
	}
	a.attestMu.Lock()
	if a.attestNonce == nonce {
		a.attestNonce = ""
	}
	a.attestMu.Unlock()
	a.log.Info("TPM quote submitted", "indexes", ev.Indexes)
}

// runTPMQuote shells out to tpm2-tools because that is the portable way to talk
// to a TPM on both Linux (device or swtpm TCTI) and provisioned Windows hosts.
func (a *Agent) runTPMQuote(ctx context.Context, nonceHex string) (tpmquote.Evidence, error) {
	dir, err := os.MkdirTemp("", "tg-quote-")
	if err != nil {
		return tpmquote.Evidence{}, err
	}
	defer os.RemoveAll(dir)
	attestPath := filepath.Join(dir, "attest.bin")
	sigPath := filepath.Join(dir, "sig.bin")
	pcrPath := filepath.Join(dir, "pcr.bin")
	env := os.Environ()
	if a.opts.TPMQuoteTCTI != "" {
		env = append(env, "TPM2TOOLS_TCTI="+a.opts.TPMQuoteTCTI)
	}
	qctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	quote := exec.CommandContext(qctx, "tpm2_quote",
		"-c", a.opts.TPMQuoteAK,
		"-l", "sha256:0,4,7",
		"-q", nonceHex,
		"-m", attestPath,
		"-s", sigPath,
		"-g", "sha256",
		"-p", "")
	quote.Env = env
	if out, err := quote.CombinedOutput(); err != nil {
		return tpmquote.Evidence{}, fmt.Errorf("tpm2_quote: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	defer func() {
		flush := exec.CommandContext(context.Background(), "tpm2_flushcontext", "-t")
		flush.Env = env
		_ = flush.Run()
	}()
	read := exec.CommandContext(qctx, "tpm2_pcrread", "sha256:0,4,7", "-o", pcrPath)
	read.Env = env
	if out, err := read.CombinedOutput(); err != nil {
		return tpmquote.Evidence{}, fmt.Errorf("tpm2_pcrread: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	attest, err := os.ReadFile(attestPath)
	if err != nil {
		return tpmquote.Evidence{}, err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return tpmquote.Evidence{}, err
	}
	pcr, err := os.ReadFile(pcrPath)
	if err != nil {
		return tpmquote.Evidence{}, err
	}
	return tpmquote.Evidence{Attest: attest, Signature: sig, PCR: pcr, Indexes: []int{0, 4, 7}}, nil
}

// ensure the base64 import is kept for future use by callers
var _ = base64.StdEncoding
