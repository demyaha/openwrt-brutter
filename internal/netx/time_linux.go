package netx

import (
	"time"

	"golang.org/x/sys/unix"
)

func enableTimestamps(fd int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1)
}

// arrival reads SCM_TIMESTAMPNS, falling back to now.
func arrival(oob []byte) time.Time {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err == nil {
		for _, m := range messages {
			if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_TIMESTAMPNS &&
				len(m.Data) >= 16 {
				ts := *(*unix.Timespec)(unsafePointer(m.Data))
				return time.Unix(int64(ts.Sec), int64(ts.Nsec))
			}
		}
	}
	return time.Now()
}
