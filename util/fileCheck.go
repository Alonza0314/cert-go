package util

import "os"

func FileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}
