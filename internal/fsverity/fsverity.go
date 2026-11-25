// Package fsverity enables Linux fs-verity on published files.
//
// fs-verity builds a Merkle tree for a file and makes it read-only: writes and
// truncates fail with EPERM, and every page read (including mmap) is verified
// against the tree, so corrupted data is refused with EIO/SIGBUS. Applying it at
// the end of a release hardens the tree beyond "nobody may write": even if the
// storage is tampered with out of band, readers get an error instead of
// attacker content.
//
// It is optional because it needs CONFIG_FS_VERITY in the kernel and the
// filesystem must be created with the "verity" feature (ext4, f2fs, btrfs).
package fsverity

import "errors"

// ErrUnsupported means the running kernel or the filesystem has no fs-verity
// support, or the object is not a regular file on such a filesystem.
var ErrUnsupported = errors.New("fs-verity: not supported by this kernel or filesystem")

// Status is the result of probing a directory for fs-verity support.
type Status struct {
	Supported bool
	Reason    string
}

// Unavailable is a convenience check.
func (s Status) Unavailable() bool { return !s.Supported }
