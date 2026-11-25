//go:build windows

package watch

import (
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

const notifyMask = windows.FILE_NOTIFY_CHANGE_FILE_NAME |
	windows.FILE_NOTIFY_CHANGE_DIR_NAME |
	windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
	windows.FILE_NOTIFY_CHANGE_SIZE |
	windows.FILE_NOTIFY_CHANGE_CREATION |
	windows.FILE_NOTIFY_CHANGE_SECURITY

const bufSize = 64 * 1024

type watcher struct {
	handle windows.Handle
	event  windows.Handle
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
}

// Watch monitors root recursively and calls onChange whenever the tree changes.
// It uses overlapped I/O so Close never blocks on a pending read: the read is
// cancelled explicitly and the worker goroutine is given a moment to exit.
func Watch(root string, onChange func()) (Watcher, error) {
	rootPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(rootPtr,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0)
	if err != nil {
		return nil, err
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	w := &watcher{handle: h, event: ev, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		buf := make([]byte, bufSize)
		ov := new(windows.Overlapped)
		ov.HEvent = ev
		for {
			select {
			case <-w.stop:
				return
			default:
			}
			var returned uint32
			callErr := windows.ReadDirectoryChanges(h, &buf[0], bufSize, true,
				notifyMask, &returned, ov, 0)
			if callErr != nil && callErr != windows.ERROR_IO_PENDING {
				if callErr == windows.ERROR_INVALID_HANDLE || callErr == windows.ERROR_OPERATION_ABORTED {
					return
				}
				time.Sleep(200 * time.Millisecond)
				continue
			}
			if _, werr := windows.WaitForSingleObject(ev, windows.INFINITE); werr != nil {
				return
			}
			select {
			case <-w.stop:
				return
			default:
			}
			var done uint32
			if err := windows.GetOverlappedResult(h, ov, &done, false); err != nil {
				if err == windows.ERROR_OPERATION_ABORTED || err == windows.ERROR_INVALID_HANDLE {
					return
				}
				// Buffer overflow and other transient errors: report and retry.
				onChange()
				continue
			}
			if done > 0 {
				onChange()
			}
		}
	}()
	return w, nil
}

// Close cancels the pending read and releases the handles without blocking on
// a synchronous directory read.
func (w *watcher) Close() error {
	w.once.Do(func() { close(w.stop) })
	_ = windows.CancelIoEx(w.handle, nil)
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
	}
	_ = windows.CloseHandle(w.event)
	return windows.CloseHandle(w.handle)
}
