//go:build windows

package secret

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

var errRotationLockBusy = errors.New("secret key rotation lock is held by another process")

func lockFile(file *os.File) error {
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return errRotationLockBusy
		}

		return err
	}

	return nil
}

func unlockFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}

func syncDir(dirPath string) error {
	return nil
}
