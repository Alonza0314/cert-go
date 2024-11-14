package util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/Alonza0314/cert-go/logger"
)

func ReadCertificate(certPath string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		logger.Error("ReadCertificate", err.Error())
		return nil, err
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		logger.Error("ReadCertificate", "failed to decode PEM block")
		return nil, errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Error("ReadCertificate", err.Error())
		return nil, err
	}

	return cert, nil
}
