//go:build linux

package fsverity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ioctl numbers from linux/fsverity.h.
//
//	FS_IOC_ENABLE_VERITY  = _IOW('f', 133, struct fsverity_enable_arg)  -> 0x40806685
//	FS_IOC_MEASURE_VERITY = _IOWR('f', 134, struct fsverity_digest)     -> 0xC0046686
const (
	fsIOCEnableVerity  = 0x40806685
	fsIOCMeasureVerity = 0xC0046686
	hashAlgSHA256      = 1
	blockSize4096      = 4096
	digestMaxSize      = 64
)

// enableArg mirrors struct fsverity_enable_arg (128 bytes on 64-bit).
type enableArg struct {
	Version       uint32
	HashAlgorithm uint32
	BlockSize     uint32
	SaltSize      uint32
	SaltPtr       uint64
	SigSize       uint32
	Reserved1     uint32
	SigPtr        uint64
	Reserved2     [11]uint64
}

// digestArg mirrors struct fsverity_digest followed by the digest bytes.
type digestArg struct {
	Algorithm uint16
	Size      uint16
	Digest    [digestMaxSize]byte
}

func ioctl(fd uintptr, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// IsVerity reports whether the file already has fs-verity enabled.
func IsVerity(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var flags int32
	if err := ioctl(f.Fd(), unix.FS_IOC_GETFLAGS, unsafe.Pointer(&flags)); err != nil {
		if errors.Is(err, unix.ENOTTY) {
			return false, ErrUnsupported
		}
		return false, err
	}
	return flags&unix.FS_VERITY_FL != 0, nil
}

// Enable turns on fs-verity for the file, making it read-only and verified on
// every read. Enabling an already-verified file is a no-op.
func Enable(path string) error {
	if ok, err := IsVerity(path); err == nil && ok {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	arg := enableArg{Version: 1, HashAlgorithm: hashAlgSHA256, BlockSize: blockSize4096}
	err = ioctl(f.Fd(), fsIOCEnableVerity, unsafe.Pointer(&arg))
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, unix.EEXIST):
		return nil
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOTTY):
		return ErrUnsupported
	default:
		return fmt.Errorf("fs-verity: enable %s: %w", path, err)
	}
}

// Digest returns the fs-verity file digest (Merkle tree root bound to the file
// descriptor) as hex, or an empty string when verity is not enabled.
func Digest(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	arg := digestArg{Size: digestMaxSize}
	if err := ioctl(f.Fd(), fsIOCMeasureVerity, unsafe.Pointer(&arg)); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTTY) {
			return "", ErrUnsupported
		}
		return "", err
	}
	if int(arg.Size) > digestMaxSize {
		return "", fmt.Errorf("fs-verity: digest size %d exceeds buffer", arg.Size)
	}
	return hex.EncodeToString(arg.Digest[:arg.Size]), nil
}

// Probe checks whether a directory can hold fs-verity files by enabling verity
// on a throwaway empty file. The file is removed afterwards (verity files can
// still be unlinked).
func Probe(dir string) Status {
	f, err := os.CreateTemp(dir, ".tg-verity-probe-")
	if err != nil {
		// The state directory may not exist yet on a fresh node.
		if mkErr := os.MkdirAll(dir, 0o750); mkErr != nil {
			return Status{Reason: err.Error()}
		}
		f, err = os.CreateTemp(dir, ".tg-verity-probe-")
		if err != nil {
			return Status{Reason: err.Error()}
		}
	}
	name := f.Name()
	_ = f.Close()
	defer os.Remove(name)
	if err := Enable(name); err != nil {
		return Status{Reason: err.Error()}
	}
	return Status{Supported: true, Reason: "kernel and filesystem support fs-verity"}
}
