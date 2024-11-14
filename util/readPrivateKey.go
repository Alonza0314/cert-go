package util

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/Alonza0314/cert-go/logger"
)

func ReadPrivateKey(keyPath string) (*ecdsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		logger.Error("ReadPrivateKey", err.Error())
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		logger.Error("ReadPrivateKey", "failed to decode PEM block")
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		logger.Error("ReadPrivateKey", err.Error())
		return nil, err
	}

	return privateKey, nil
}
