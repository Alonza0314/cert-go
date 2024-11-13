package util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/Alonza0314/cert-go/logger"
)

func ReadCsr(csrPath string) ([]byte, error) {
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		logger.Error("ReadCsr: " + err.Error())
		return nil, err
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		logger.Error("ReadCsr: failed to decode PEM block")
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE REQUEST" {
		logger.Error("ReadCsr: invalid PEM type: " + block.Type)
		return nil, errors.New("invalid PEM type")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		logger.Error("ReadCsr: " + err.Error())
		return nil, err
	}

	if err := csr.CheckSignature(); err != nil {
		logger.Error("ReadCsr: " + err.Error())
		return nil, err
	}

	return block.Bytes, nil
}
