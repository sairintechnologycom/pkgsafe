//go:build windows
package sandbox

import (
	"os"
	"syscall"
	"time"
)

func getAccessTime(fi os.FileInfo) time.Time {
	stat, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return fi.ModTime()
	}
	return time.Unix(0, stat.LastAccessTime.Nanoseconds())
}
