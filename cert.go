package certgo

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/Alonza0314/cert-go/logger"
	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
)

func signCertificate(cfg model.Certificate) ([]byte, error) {
	// create certificate template
	var template *x509.Certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		logger.Error("signCertificate: " + err.Error())
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(cfg.ValidityYears, cfg.ValidityMonth, cfg.ValidityDay)

	template = &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{cfg.Organization},
			CommonName:   cfg.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              cfg.KeyUsage,
		ExtKeyUsage:           cfg.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  cfg.IsCA,
	}

	var certBytes []byte

	if cfg.Type == "root" {
		// root certificate self-signed
		if !util.FileExists(cfg.KeyFilePath) {
			logger.Warn("signCertificate: private key does not exist")
			cfg.ParentKey, err = CreatePrivateKey(cfg.KeyFilePath)
			if err != nil {
				logger.Error("signCertificate: " + err.Error())
				return nil, err
			}
		}
		if cfg.ParentKey == nil {
			cfg.ParentKey, err = util.ReadPrivateKey(cfg.KeyFilePath)
			if err != nil {
				logger.Error("signCertificate: " + err.Error())
				return nil, err
			}
		}

		certBytes, err = x509.CreateCertificate(rand.Reader, template, template, &cfg.ParentKey.PublicKey, cfg.ParentKey)
		if err != nil {
			logger.Error("signCertificate: " + err.Error())
			return nil, err
		}
		logger.Info("signCertificate: root certificate created")
	} else {
		// intermediate certificate or end-entity certificate
		var csrData []byte
		if !util.FileExists(cfg.CsrFilePath) {
			logger.Warn("signCertificate: CSR file does not exist")
			csrData, err = CreateCsr(cfg)
			if err != nil {
				logger.Error("signCertificate: " + err.Error())
				return nil, err
			}
		}
		if csrData == nil {
			csrData, err = util.ReadCsr(cfg.CsrFilePath)
			if err != nil {
				logger.Error("signCertificate: " + err.Error())
				return nil, err
			}
		}

		csr, err := x509.ParseCertificateRequest(csrData)
		if err != nil {
			logger.Error("signCertificate: " + err.Error())
			return nil, err
		}

		// read parent cert
		cfg.ParentCert, err = util.ReadCertificate(cfg.ParentCertPath)
		if err != nil {
			logger.Error("signCertificate: " + err.Error())
			return nil, err
		}

		// read parent key
		cfg.ParentKey, err = util.ReadPrivateKey(cfg.ParentKeyPath)
		if err != nil {
			logger.Error("signCertificate: " + err.Error())
			return nil, err
		}

		// sign certificate with parent certificate
		certBytes, err = x509.CreateCertificate(rand.Reader, template, cfg.ParentCert, csr.PublicKey, cfg.ParentKey)
		if err != nil {
			logger.Error("signCertificate: " + err.Error())
			return nil, err
		}
		logger.Info("signCertificate: intermediate certificate created")
	}

	// encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	if err := util.FileWrite(cfg.CertFilePath, certPEM, 0644); err != nil {
		logger.Error("signCertificate: " + err.Error())
		return nil, err
	}

	return certPEM, nil
}

func SignRootCertificate(yamlPath string) ([]byte, error) {
	var cfg model.CAConfig
	if err := util.ReadYamlFileToStruct(yamlPath, &cfg); err != nil {
		logger.Error("SignRootCertificate: " + err.Error())
		return nil, err
	}
	certBytes, err := signCertificate(cfg.CA.Root)
	if err != nil {
		logger.Error("SignRootCertificate: " + err.Error())
		return nil, err
	}
	return certBytes, nil
}

func SignIntermediateCertificate(yamlPath string) ([]byte, error) {
	var cfg model.CAConfig
	if err := util.ReadYamlFileToStruct(yamlPath, &cfg); err != nil {
		logger.Error("SignIntermediateCertificate: " + err.Error())
		return nil, err
	}
	certBytes, err := signCertificate(cfg.CA.Intermediate)
	if err != nil {
		logger.Error("SignIntermediateCertificate: " + err.Error())
		return nil, err
	}
	return certBytes, nil
}

func SignServerCertificate(yamlPath string) ([]byte, error) {
	var cfg model.CAConfig
	if err := util.ReadYamlFileToStruct(yamlPath, &cfg); err != nil {
		logger.Error("SignServerCertificate: " + err.Error())
		return nil, err
	}
	certBytes, err := signCertificate(cfg.CA.Server)
	if err != nil {
		logger.Error("SignServerCertificate: " + err.Error())
		return nil, err
	}
	return certBytes, nil
}

func SignClientCertificate(yamlPath string) ([]byte, error) {
	var cfg model.CAConfig
	if err := util.ReadYamlFileToStruct(yamlPath, &cfg); err != nil {
		logger.Error("SignClientCertificate: " + err.Error())
		return nil, err
	}
	certBytes, err := signCertificate(cfg.CA.Client)
	if err != nil {
		logger.Error("SignClientCertificate: " + err.Error())
		return nil, err
	}
	return certBytes, nil
}
