package certgo

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"

	"github.com/Alonza0314/cert-go/logger"
	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
)

func CreateCsr(cfg model.Certificate) ([]byte, error) {
	var privateKey *ecdsa.PrivateKey
	var err error

	// check private key exists
	if !util.FileExists(cfg.KeyFilePath) {
		logger.Warn("CreateCsr: private key does not exist")
		privateKey, err = CreatePrivateKey(cfg.KeyFilePath)
		if err != nil {
			logger.Error("CreateCsr: " + err.Error())
			return nil, err
		}
	}

	if privateKey == nil {
		privateKey, err = util.ReadPrivateKey(cfg.KeyFilePath)
		if err != nil {
			logger.Error("CreateCsr: " + err.Error())
			return nil, err
		}
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{cfg.Organization},
			CommonName:   cfg.CommonName,
		},
	}

	// create csr
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		logger.Error("CreateCsr: " + err.Error())
		return nil, err
	}

	// encode csr
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// save csr
	if err := os.WriteFile(cfg.CsrFilePath, csrPEM, 0644); err != nil {
		logger.Error("CreateCsr: " + err.Error())
		return nil, err
	}

	logger.Info("CreateCsr: csr created")
	return csrBytes, nil
}
