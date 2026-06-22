//go:build darwin
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
	return time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
}
