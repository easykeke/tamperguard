// Package landlock confines a process with the Linux Landlock LSM so that it
// cannot write outside an explicit allow-list of directories.
//
// This is the "self-protection" layer of TamperGuard: instead of (or besides)
// blocking writes system-wide with eBPF, the web server is started inside a
// Landlock domain that has no write rights on the document root. A remote code
// execution inside that process then cannot modify the protected files, even
// though the file DACLs and the process uid would allow it.
//
// The restriction is applied before exec and is inherited by all children; it
// cannot be lifted for the lifetime of the process tree.
package landlock

import "errors"

// ErrUnsupported means the running kernel has no Landlock support (or it is
// disabled in the LSM list).
var ErrUnsupported = errors.New("landlock: not supported by this platform")

// Config describes the sandbox to apply.
type Config struct {
	// WritableDirs are the only directories where the confined process may
	// create, modify, rename or delete files. Everything else becomes
	// read-only, including files that are readable today.
	WritableDirs []string
}
