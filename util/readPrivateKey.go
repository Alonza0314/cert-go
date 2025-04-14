package util

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	logger "github.com/Alonza0314/logger-go"
)

func ReadPrivateKey(keyPath string, passphrase string) (*ecdsa.PrivateKey, error) {
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

	var der []byte
	if x509.IsEncryptedPEMBlock(block) {
		der, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, err
		}
	} else {
		der = block.Bytes
	}

	privateKey, err := x509.ParseECPrivateKey(der)
	if err != nil {
		logger.Error("ReadPrivateKey", err.Error())
		return nil, err
	}

	return privateKey, nil
}
