package certgo

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/Alonza0314/cert-go/constants"
	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
	logger "github.com/Alonza0314/logger-go"
)

func signCertificate(cfg model.Certificate, keyType constants.PrivateKeyType, overwrite bool) (*x509.Certificate, error) {
	logger.Info("signCertificate", "signing certificate")

	// check if certificate exists
	if util.FileExists(cfg.CertFilePath) {
		if !overwrite {
			logger.Error("signCertificate", fmt.Sprintf("certificate already exists at %s.", cfg.CertFilePath))
			return nil, errors.New("certificate already exists")
		}
		logger.Warn("signCertificate", "certificate already exists. Overwrite it")
		if err := util.FileDelete(cfg.CertFilePath); err != nil {
			logger.Error("signCertificate", "failed to remove existing certificate: "+err.Error())
			return nil, err
		}
	}

	// create certificate template
	var template *x509.Certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		logger.Error("signCertificate", err.Error())
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
		DNSNames:              cfg.DNSNames,
		IPAddresses: func() []net.IP {
			ips := make([]net.IP, 0)
			for _, ip := range cfg.IPAddresses {
				ips = append(ips, net.ParseIP(ip))
			}
			return ips
		}(),
		URIs: func() []*url.URL {
			uris := make([]*url.URL, 0)
			for _, uri := range cfg.URIs {
				uris = append(uris, &url.URL{Host: uri})
			}
			return uris
		}(),
	}

	var certBytes []byte

	if cfg.Type == string(constants.CERT_TYPE_ROOT) {
		// root certificate self-signed
		var parentKey interface{}
		if !util.FileExists(cfg.KeyFilePath) {
			logger.Warn("signCertificate", "private key does not exist")
			parentKey, err = CreatePrivateKey(cfg.KeyFilePath, keyType, overwrite)
			if err != nil {
				return nil, err
			}
		}
		if cfg.ParentKey == nil {
			parentKey, err = util.ReadPrivateKey(cfg.KeyFilePath)
			if err != nil {
				return nil, err
			}
		}

		// check private key type is same as the key type
		if _, err := util.IsPrivateKeyTypeSame(parentKey, keyType); err != nil {
			logger.Error("signCertificate", err.Error())
			return nil, err
		}

		var publicKey interface{}
		switch keyType {
		case constants.PRIVATE_KEY_TYPE_ECDSA:
			cfg.ParentKey = parentKey.(*ecdsa.PrivateKey)
			publicKey = &cfg.ParentKey.(*ecdsa.PrivateKey).PublicKey
		case constants.PRIVATE_KEY_TYPE_RSA:
			cfg.ParentKey = parentKey.(*rsa.PrivateKey)
			publicKey = &cfg.ParentKey.(*rsa.PrivateKey).PublicKey
		}

		certBytes, err = x509.CreateCertificate(rand.Reader, template, template, publicKey, cfg.ParentKey)
		if err != nil {
			logger.Error("signCertificate", err.Error())
			return nil, err
		}
	} else {
		// intermediate certificate or end-entity certificate
		var csr *x509.CertificateRequest
		if !util.FileExists(cfg.CsrFilePath) {
			logger.Warn("signCertificate", "CSR file does not exist")
			csr, err = CreateCsr(cfg, keyType, overwrite)
			if err != nil {
				return nil, err
			}
		}
		if csr == nil {
			csr, err = util.ReadCsr(cfg.CsrFilePath)
			if err != nil {
				return nil, err
			}
		}

		if err := csr.CheckSignature(); err != nil {
			logger.Error("signCertificate", err.Error())
			return nil, err
		}

		// read parent cert
		cfg.ParentCert, err = util.ReadCertificate(cfg.ParentCertPath)
		if err != nil {
			return nil, err
		}

		// read parent key
		cfg.ParentKey, err = util.ReadPrivateKey(cfg.ParentKeyPath)
		if err != nil {
			return nil, err
		}

		// sign certificate with parent certificate
		certBytes, err = x509.CreateCertificate(rand.Reader, template, cfg.ParentCert, csr.PublicKey, cfg.ParentKey)
		if err != nil {
			logger.Error("signCertificate", err.Error())
			return nil, err
		}
	}

	// encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// create directory if it doesn't exist
	if !util.FileDirExists(cfg.CertFilePath) {
		logger.Warn("signCertificate", util.FileDir(cfg.CertFilePath)+" directory not exists, creating...")
		if err := util.FileDirCreate(cfg.CertFilePath); err != nil {
			return nil, err
		}
		logger.Info("signCertificate", util.FileDir(cfg.CertFilePath)+" directory created")
	}

	// write certificate file
	if err := util.FileWrite(cfg.CertFilePath, certPEM, 0644); err != nil {
		return nil, err
	}

	logger.Info("signCertificate", cfg.Type+" certificate signed")

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		logger.Error("signCertificate", err.Error())
		return nil, err
	}

	logger.Info("signCertificate", fmt.Sprintf("%s certificate for CN=%s (Org=%s), valid from %s to %s",
		cfg.Type,
		cfg.CommonName,
		cfg.Organization,
		template.NotBefore.Format("2006-01-02"),
		template.NotAfter.Format("2006-01-02"),
	))
	return cert, nil
}

func SignCertificate(certType constants.CertType, keyType constants.PrivateKeyType, yamlPath string, overwrite bool) (*x509.Certificate, error) {
	var cfg model.CAConfig
	if err := util.ReadYamlFileToStruct(yamlPath, &cfg); err != nil {
		return nil, err
	}

	switch certType {
	case constants.CERT_TYPE_ROOT:
		return signCertificate(cfg.CA.Root, keyType, overwrite)
	case constants.CERT_TYPE_INTERMEDIATE:
		return signCertificate(cfg.CA.Intermediate, keyType, overwrite)
	case constants.CERT_TYPE_SERVER:
		return signCertificate(cfg.CA.Server, keyType, overwrite)
	case constants.CERT_TYPE_CLIENT:
		return signCertificate(cfg.CA.Client, keyType, overwrite)
	}

	return nil, errors.New("invalid certificate type")
}
