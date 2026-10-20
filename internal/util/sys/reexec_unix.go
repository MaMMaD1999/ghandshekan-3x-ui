//go:build linux || darwin

package sys

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Keep PID 1 alive in containers while replacing the complete running binary.
func Reexec() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	path = strings.TrimSuffix(path, " (deleted)")
	if folder := os.Getenv("XUI_MAIN_FOLDER"); folder != "" {
		path = filepath.Join(folder, "x-ui")
	}
	return syscall.Exec(path, os.Args, os.Environ())
}
