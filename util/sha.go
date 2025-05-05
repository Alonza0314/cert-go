package util

import (
	"crypto/sha1"
)

func hashSHA1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}