//go:build windows

package sensors

import (
	"os"
)

// Windows: Go's FileInfo.Sys() does not expose atime portably across
// filesystems; return empty and rely on mtime/size change detection.
func atimeOf(fi os.FileInfo) string {
	return ""
}
