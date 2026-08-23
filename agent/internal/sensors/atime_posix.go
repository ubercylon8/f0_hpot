//go:build !windows

package sensors

import (
	"syscall"
	"time"
)

func timeFromStatx(st *syscall.Stat_t) time.Time {
	return time.Unix(st.Atim.Sec, st.Atim.Nsec)
}
