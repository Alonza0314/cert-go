package certgo

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/Alonza0314/cert-go/constants"
	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
	logger "github.com/Alonza0314/logger-go"
)

func CreateCsr(cfg model.Certificate, keyType constants.PrivateKeyType, overwrite bool) (*x509.CertificateRequest, error) {
	logger.Info("CreateCsr", "creating csr")

	// check csr exists
	if util.FileExists(cfg.CsrFilePath) {
		if !overwrite {
			logger.Error("CreateCsr", fmt.Sprintf("CSR already exists at %s.", cfg.CertFilePath))
			return nil, errors.New("csr already exists")
		}
		logger.Warn("CreateCsr", "CSR already exists. Overwrite it")
		if err := util.FileDelete(cfg.CsrFilePath); err != nil {
			logger.Error("CreateCsr", "failed to remove existing CSR: "+err.Error())
			return nil, err
		}
	}

	var privateKey interface{}
	var err error

	// check private key exists
	if !util.FileExists(cfg.KeyFilePath) {
		logger.Warn("CreateCsr", "private key does not exist")
		privateKey, err = CreatePrivateKey(cfg.KeyFilePath, keyType, overwrite)
		if err != nil {
			return nil, err
		}
	}

	if privateKey == nil {
		privateKey, err = util.ReadPrivateKey(cfg.KeyFilePath)
		if err != nil {
			return nil, err
		}
	}

	// check private key type is same as the key type
	if _, err := util.IsPrivateKeyTypeSame(privateKey, keyType); err != nil {
		logger.Error("CreateCsr", err.Error())
		return nil, err
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
		logger.Error("CreateCsr", err.Error())
		return nil, err
	}

	// encode csr
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// create directory exists
	if !util.FileDirExists(cfg.CsrFilePath) {
		logger.Warn("CreateCsr", util.FileDir(cfg.CsrFilePath)+" directory not exists, creating...")
		if err := util.FileDirCreate(cfg.CsrFilePath); err != nil {
			return nil, err
		}
		logger.Info("CreateCsr", util.FileDir(cfg.CsrFilePath)+" directory created")
	}

	// save csr
	if err := util.FileWrite(cfg.CsrFilePath, csrPEM, 0644); err != nil {
		return nil, err
	}

	logger.Info("CreateCsr", "csr created")

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		logger.Error("CreateCsr", err.Error())
		return nil, err
	}
	return csr, nil
}
