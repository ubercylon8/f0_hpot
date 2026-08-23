//go:build !windows

package sensors

import (
	"os"
	"syscall"
	"time"
)

func atimeOf(fi os.FileInfo) string {
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		return time.Unix(sys.Atim.Sec, sys.Atim.Nsec).UTC().Format(time.RFC3339Nano)
	}
	return ""
}
