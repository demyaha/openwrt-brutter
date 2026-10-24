//go:build !linux

package netx

import "time"

func enableTimestamps(int) error { return nil }

func arrival([]byte) time.Time { return time.Now() }
