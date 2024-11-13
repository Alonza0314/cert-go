package certgo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/Alonza0314/cert-go/logger"
	"github.com/Alonza0314/cert-go/util"
)

func CreatePrivateKey(keyPath string) (*ecdsa.PrivateKey, error) {
	// generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Error("CreatePrivateKey: " + err.Error())
		return nil, err
	}

	// encode private key
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		logger.Error("CreatePrivateKey: " + err.Error())
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	// save private key
	if err := util.FileWrite(keyPath, keyPEM, 0644); err != nil {
		logger.Error("CreatePrivateKey: " + err.Error())
		return nil, err
	}

	logger.Info("CreatePrivateKey: private key created")
	return privateKey, nil
}