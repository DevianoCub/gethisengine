//go:build windows

package sqlite

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// openSource opens a browser database with permissive sharing flags. Chrome
// and friends keep their files open while running; a plain os.Open would fail
// with a sharing violation.
func openSource(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func isNotExist(err error) bool {
	return os.IsNotExist(err) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}
