package util

import (
	"crypto/sha1"
)

func HashSHA1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}
