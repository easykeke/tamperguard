package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. These are deliberately at the OWASP-recommended lower
// bound: the control plane is a small service, login is rare, and we would
// rather burn 64 MiB for 100 ms than risk a password database that cracks in
// hours. Raise memory when running on a dedicated host.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum)), nil
}

// VerifyPassword checks password against a PHC-format argon2id hash in
// constant time with respect to the hash comparison.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var memory uint32
	var iters uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iters, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iters, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ParsePHCParams is used by tests and by the "check config" command.
func ParsePHCParams(encoded string) (memory uint32, iters uint32, threads uint8, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, errors.New("password: not an argon2id hash")
	}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iters, &threads)
	return memory, iters, threads, err
}

// dummyHash is compared against when the username does not exist, so that a
// login probe cannot distinguish "no such user" from "wrong password" by
// timing.
var dummyHash string

func init() {
	h, err := HashPassword("dummy-password-for-timing-equalisation")
	if err == nil {
		dummyHash = h
	} else {
		// Fall back to a syntactically valid but unusable hash.
		dummyHash = "$argon2id$v=19$m=65536,t=1,p=4$" +
			base64.RawStdEncoding.EncodeToString(make([]byte, argonSaltLen)) + "$" +
			base64.RawStdEncoding.EncodeToString(make([]byte, argonKeyLen))
	}
}

// parseUint is a tiny helper used by query parsing.
func parseUint(s string, def uint64) uint64 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return def
	}
	return v
}
