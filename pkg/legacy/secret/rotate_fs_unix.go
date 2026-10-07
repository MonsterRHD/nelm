//go:build !windows

package secret

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var errRotationLockBusy = errors.New("secret key rotation lock is held by another process")

func lockFile(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return errRotationLockBusy
		}

		return err
	}

	return nil
}

func unlockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

func syncDir(dirPath string) error {
	dir, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer dir.Close()

	return unix.Fsync(int(dir.Fd()))
}
