//go:build !windows

package watch

// Watch is unavailable outside Windows; the Linux enforcers have their own
// kernel event sources.
func Watch(root string, onChange func()) (Watcher, error) {
	return nil, ErrUnsupported
}
