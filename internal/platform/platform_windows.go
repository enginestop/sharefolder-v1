package platform

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
)

func Lock(f *os.File) error {
	var o windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &o)
}
func Disk(path string) (total, free int64, err error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, 0, e
	}
	var a, b, c uint64
	e = windows.GetDiskFreeSpaceEx(p, &a, &b, &c)
	return int64(b), int64(a), e
}
func SameFS(a, b string) (bool, error) {
	return strings.EqualFold(filepath.VolumeName(a), filepath.VolumeName(b)), nil
}
func SyncDir(path string) error { return nil }
func Private(path string) error { return nil }
