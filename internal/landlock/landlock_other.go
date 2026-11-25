//go:build !linux

package landlock

// ABI is only meaningful on Linux.
func ABI() (int, error) { return 0, ErrUnsupported }

// Restrict is a no-op error on platforms without Landlock.
func Restrict(cfg Config) error { return ErrUnsupported }

// Exec is unavailable on platforms without Landlock.
func Exec(cfg Config, argv []string, env []string) error { return ErrUnsupported }
