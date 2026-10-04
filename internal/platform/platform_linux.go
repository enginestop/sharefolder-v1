package platform

import (
	"golang.org/x/sys/unix"
	"os"
)

func Lock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func Disk(path string) (total, free int64, err error) {
	var s unix.Statfs_t
	err = unix.Statfs(path, &s)
	return int64(s.Blocks) * s.Bsize, int64(s.Bavail) * s.Bsize, err
}
func SameFS(a, b string) (bool, error) {
	var x, y unix.Stat_t
	if e := unix.Stat(a, &x); e != nil {
		return false, e
	}
	if e := unix.Stat(b, &y); e != nil {
		return false, e
	}
	return x.Dev == y.Dev, nil
}
func SyncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func Private(path string) error {
	info, e := os.Stat(path)
	if e != nil {
		return e
	}
	if info.Mode().Perm()&0077 != 0 {
		return os.ErrPermission
	}
	return nil
}
