package util

import (
	"io/fs"
	"os"
)

func FileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

func FileWrite(filePath string, data []byte, code fs.FileMode) error {
	return os.WriteFile(filePath, data, code)
}
