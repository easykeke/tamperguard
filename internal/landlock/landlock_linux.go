//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

// writeRights are the access rights this package governs. Read and execute are
// deliberately not handled: the process keeps its normal read access, only
// write-class operations become deny-by-default.
func writeRights(abi int) uint64 {
	m := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		m |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		m |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return m
}

// fileRights are the write-class rights that make sense on a single file.
func fileRights(abi int) uint64 {
	m := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE)
	if abi >= 3 {
		m |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return m
}

// ABI returns the Landlock ABI version supported by the running kernel.
// ErrUnsupported means the LSM is absent or disabled.
func ABI() (int, error) {
	r, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0,
		unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		switch errno {
		case unix.ENOSYS, unix.EOPNOTSUPP, unix.EINVAL:
			return 0, ErrUnsupported
		default:
			return 0, errno
		}
	}
	return int(r), nil
}

// Restrict confines the current process. It must be called before the work
// starts: file descriptors opened earlier keep their rights, and children
// inherit the domain.
func Restrict(cfg Config) error {
	abi, err := ABI()
	if err != nil {
		return err
	}
	handled := writeRights(abi)

	// Kernels before the "scoped" field was added (ABI < 6) only know the
	// 8-byte ruleset attribute; newer ones expect the full structure.
	var attrPtr unsafe.Pointer
	var attrSize uintptr
	if abi >= 6 {
		attr := unix.LandlockRulesetAttr{Access_fs: handled}
		attrPtr = unsafe.Pointer(&attr)
		attrSize = unsafe.Sizeof(attr)
	} else {
		attr := struct{ handledAccessFS uint64 }{handledAccessFS: handled}
		attrPtr = unsafe.Pointer(&attr)
		attrSize = unsafe.Sizeof(attr)
	}

	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(attrPtr), attrSize, 0)
	if errno != 0 {
		return fmt.Errorf("landlock: create ruleset: %w", errno)
	}
	defer unix.Close(int(fd))

	for _, dir := range cfg.WritableDirs {
		dirFD, err := unix.Open(dir, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("landlock: open writable dir %s: %w", dir, err)
		}
		// A rule attached to a non-directory may only grant file-level rights;
		// combining it with MAKE_* is rejected by the kernel (EINVAL).
		allowed := handled
		if st, statErr := os.Stat(dir); statErr == nil && !st.IsDir() {
			allowed = fileRights(abi)
		}
		rule := unix.LandlockPathBeneathAttr{
			Allowed_access: allowed,
			Parent_fd:      int32(dirFD),
		}
		_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd,
			unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		unix.Close(dirFD)
		if errno != 0 {
			return fmt.Errorf("landlock: allow writes under %s: %w", dir, errno)
		}
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("landlock: set no_new_privs: %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return fmt.Errorf("landlock: restrict self: %w", errno)
	}
	return nil
}

// Exec confines the current process and replaces it with argv[0]. It never
// returns on success.
func Exec(cfg Config, argv []string, env []string) error {
	if len(argv) == 0 {
		return errors.New("landlock: no command given")
	}
	if err := Restrict(cfg); err != nil {
		return err
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	return unix.Exec(path, argv, env)
}
