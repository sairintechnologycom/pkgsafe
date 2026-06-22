//go:build linux
package sandbox

import (
	"os"
	"syscall"
	"time"
)

func getAccessTime(fi os.FileInfo) time.Time {
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fi.ModTime()
	}
	return time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
}
