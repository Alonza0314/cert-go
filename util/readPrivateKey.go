package util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/Alonza0314/cert-go/constants"
	logger "github.com/Alonza0314/logger-go"
)

func ReadPrivateKey(keyPath string) (interface{}, error) {
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

	switch block.Type {
	case string(constants.PRIVATE_KEY_TYPE_ECDSA):
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			logger.Error("ReadPrivateKey", err.Error())
			return nil, err
		}
		return privateKey, nil

	case string(constants.PRIVATE_KEY_TYPE_RSA):
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			logger.Error("ReadPrivateKey", err.Error())
			return nil, err
		}
		return privateKey, nil

	default:
		logger.Error("ReadPrivateKey", "unsupported private key type: "+block.Type)
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}
