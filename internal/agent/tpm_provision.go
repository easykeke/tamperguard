package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ProvisionAK creates an endorsement key and an attestation key on the TPM and
// returns the AK context path plus its PEM public key. It is called during
// enrolment when --tpm-auto-ak is set, so operators do not have to run
// tpm2-createek/createak by hand.
func ProvisionAK(stateDir, tcti string) (ctxPath, pubPEM string, err error) {
	dir := filepath.Join(stateDir, "tpm")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	env := os.Environ()
	if tcti != "" {
		env = append(env, "TPM2TOOLS_TCTI="+tcti)
	}
	run := func(name string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	ek := filepath.Join(dir, "ek.ctx")
	ak := filepath.Join(dir, "ak.ctx")
	pemPath := filepath.Join(dir, "ak.pem")
	if err := run("tpm2_createek", "-G", "ecc", "-c", ek); err != nil {
		return "", "", err
	}
	if err := run("tpm2_createak", "-C", ek, "-G", "ecc", "-g", "sha256",
		"-s", "ecdsa", "-c", ak, "-u", pemPath, "-f", "pem"); err != nil {
		return "", "", err
	}
	// Release the transient provisioning handles; the TPM has few slots.
	_ = run("tpm2_flushcontext", "-t")
	pem, err := os.ReadFile(pemPath)
	if err != nil {
		return "", "", err
	}
	return ak, string(pem), nil
}
