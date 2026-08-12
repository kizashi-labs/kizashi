//go:build !windows

package health

import "syscall"

type diskStat struct {
	Free uint64
}

func getDiskStat(path string, s *diskStat) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return err
	}
	s.Free = stat.Bavail * uint64(stat.Bsize)
	return nil
}
