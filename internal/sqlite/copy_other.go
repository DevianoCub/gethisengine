//go:build !windows

package sqlite

import "os"

func openSource(path string) (*os.File, error) {
	return os.Open(path)
}

func isNotExist(err error) bool {
	return os.IsNotExist(err)
}
