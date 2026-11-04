//go:build !unix && !windows

package cabundle

import (
	"errors"
	"os"
)

// Without an OS file lock the seqno cannot be kept monotonic across
// processes, so refuse rather than silently lose rollback protection.
func lockFile(*os.File) error {
	return errors.New("file locking is not supported on this platform")
}

func unlockFile(*os.File) error { return nil }
