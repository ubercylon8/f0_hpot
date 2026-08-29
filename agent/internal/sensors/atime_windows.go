//go:build windows

package sensors

import (
	"os"
	"syscall"
	"time"
)

// Windows does expose last-access time: FileInfo.Sys() carries a
// *syscall.Win32FileAttributeData with LastAccessTime. The previous stub
// returned "" unconditionally, which quietly reduced planted_credential
// and file_watch to write/delete detection on Windows — the read case,
// which is the whole point of a bait credential, never fired.
//
// Caveat this cannot fix in code: NTFS last-access updates are disabled by
// default on modern Windows (`fsutil behavior query DisableLastAccess`
// usually reports "2 (System Managed, Disabled)"). Reading a file then
// leaves atime untouched no matter what we do here, so the sensor probes
// the behaviour at startup and says so rather than pretending to watch.
func atimeOf(fi os.FileInfo) string {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return ""
	}
	return time.Unix(0, d.LastAccessTime.Nanoseconds()).UTC().Format(time.RFC3339Nano)
}
