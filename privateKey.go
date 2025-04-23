package certgo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/Alonza0314/cert-go/constants"
	"github.com/Alonza0314/cert-go/util"
	logger "github.com/Alonza0314/logger-go"
)

func CreatePrivateKey(keyPath string, keyType constants.PrivateKeyType, overwrite bool) (interface{}, error) {
	logger.Info("CreatePrivateKey", "creating private key")

	// check if private key exists
	if util.FileExists(keyPath) {
		if !overwrite {
			logger.Error("CreatePrivateKey", fmt.Sprintf("private key already exists at %s.", keyPath))
			return nil, errors.New("private key already exists")
		}
		logger.Warn("CreatePrivateKey", "private key already exists. Overwrite it")
		if err := util.FileDelete(keyPath); err != nil {
			logger.Error("CreatePrivateKey", "failed to remove existing private key: "+err.Error())
			return nil, err
		}
	}

	var privateKey interface{}
	var keyBytes []byte

	// generate private key
	switch keyType {
	case constants.PRIVATE_KEY_TYPE_ECDSA:
		logger.Info("CreatePrivateKey", "generating ECDSA private key")
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			logger.Error("CreatePrivateKey", err.Error())
			return nil, err
		}
		privateKey = ecdsaKey

		keyBytes, err = x509.MarshalECPrivateKey(ecdsaKey)
		if err != nil {
			logger.Error("CreatePrivateKey", err.Error())
			return nil, err
		}

	case constants.PRIVATE_KEY_TYPE_RSA:
		logger.Info("CreatePrivateKey", "generating RSA private key")
		rsaKey, err := rsa.GenerateKey(rand.Reader, constants.PRIVATE_KEY_LENGTH)
		if err != nil {
			logger.Error("CreatePrivateKey", err.Error())
			return nil, err
		}
		privateKey = rsaKey

		keyBytes = x509.MarshalPKCS1PrivateKey(rsaKey)

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  string(keyType),
		Bytes: keyBytes,
	})

	// check directory exists
	if !util.FileDirExists(keyPath) {
		logger.Warn("CreatePrivateKey", util.FileDir(keyPath)+" directory not exists, creating...")
		if err := util.FileDirCreate(keyPath); err != nil {
			return nil, err
		}
		logger.Info("CreatePrivateKey", util.FileDir(keyPath)+" directory created")
	}

	// save private key
	if err := util.FileWrite(keyPath, keyPEM, 0644); err != nil {
		return nil, err
	}

	logger.Info("CreatePrivateKey", "private key created")
	return privateKey, nil
}
