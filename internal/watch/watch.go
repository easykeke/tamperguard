// Package watch provides a small directory-notification primitive used by the
// Windows self-heal loop. On Linux the inotify/fanotify backends already have
// their own event path, so the stub there reports ErrUnsupported.
package watch

import "errors"

// ErrUnsupported means the platform has no watcher implementation.
var ErrUnsupported = errors.New("watch: not supported on this platform")

// Watcher is a running directory monitor.
type Watcher interface {
	Close() error
}

// ErrClosed is returned when the underlying handle is gone.
var ErrClosed = errors.New("watch: closed")
