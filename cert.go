package certgo

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
	logger "github.com/Alonza0314/logger-go"
)

// CertificateType 表示证书类型
type CertificateType string

const (
	CertTypeRoot         CertificateType = "root"
	CertTypeIntermediate CertificateType = "intermediate"
	CertTypeServer       CertificateType = "server"
	CertTypeClient       CertificateType = "client"
)

func signCertificate(cfg model.Certificate) (*x509.Certificate, error) {
	logger.Info("signCertificate", "signing certificate")

	// 检查证书是否已存在
	if util.FileExists(cfg.CertFilePath) {
		logger.Warn("signCertificate", "certificate already exists")
		return nil, ErrCertExists
	}

	// 创建证书模板
	template, err := createCertificateTemplate(cfg)
	if err != nil {
		return nil, NewCertError("create certificate template", err)
	}

	var certBytes []byte
	if cfg.Type == string(CertTypeRoot) {
		certBytes, err = signRootCertificate(template, cfg)
	} else {
		certBytes, err = signNonRootCertificate(template, cfg)
	}
	if err != nil {
		return nil, err
	}

	// 编码证书为PEM格式
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// 确保目录存在
	if err := ensureDirectoryExists(cfg.CertFilePath); err != nil {
		return nil, err
	}

	// 写入证书文件
	if err := util.FileWrite(cfg.CertFilePath, certPEM, 0644); err != nil {
		return nil, NewCertError("write certificate file", err)
	}

	logger.Info("signCertificate", cfg.Type+" certificate signed")

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, NewCertError("parse certificate", err)
	}
	return cert, nil
}

func createCertificateTemplate(cfg model.Certificate) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, NewCertError("generate serial number", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(cfg.ValidityYears, cfg.ValidityMonth, cfg.ValidityDay)

	return &x509.Certificate{
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
		IPAddresses:           parseIPAddresses(cfg.IPAddresses),
		URIs:                  parseURIs(cfg.URIs),
	}, nil
}

func parseIPAddresses(ips []string) []net.IP {
	result := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			result = append(result, parsedIP)
		}
	}
	return result
}

func parseURIs(uris []string) []*url.URL {
	result := make([]*url.URL, 0, len(uris))
	for _, uri := range uris {
		result = append(result, &url.URL{Host: uri})
	}
	return result
}

func signRootCertificate(template *x509.Certificate, cfg model.Certificate) ([]byte, error) {
	if !util.FileExists(cfg.KeyFilePath) {
		logger.Warn("signCertificate", "private key does not exist")
		var err error
		cfg.ParentKey, err = CreatePrivateKey(cfg.KeyFilePath)
		if err != nil {
			return nil, NewCertError("create private key", err)
		}
	} else if cfg.ParentKey == nil {
		var err error
		cfg.ParentKey, err = util.ReadPrivateKey(cfg.KeyFilePath)
		if err != nil {
			return nil, NewCertError("read private key", err)
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &cfg.ParentKey.PublicKey, cfg.ParentKey)
	if err != nil {
		return nil, NewCertError("create root certificate", err)
	}
	return certBytes, nil
}

func signNonRootCertificate(template *x509.Certificate, cfg model.Certificate) ([]byte, error) {
	csr, err := getOrCreateCSR(cfg)
	if err != nil {
		return nil, err
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, NewCertError("check CSR signature", err)
	}

	parentCert, err := util.ReadCertificate(cfg.ParentCertPath)
	if err != nil {
		return nil, NewCertError("read parent certificate", err)
	}

	parentKey, err := util.ReadPrivateKey(cfg.ParentKeyPath)
	if err != nil {
		return nil, NewCertError("read parent private key", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, csr.PublicKey, parentKey)
	if err != nil {
		return nil, NewCertError("create certificate", err)
	}
	return certBytes, nil
}

func getOrCreateCSR(cfg model.Certificate) (*x509.CertificateRequest, error) {
	if !util.FileExists(cfg.CsrFilePath) {
		logger.Warn("signCertificate", "CSR file does not exist")
		return CreateCsr(cfg)
	}
	return util.ReadCsr(cfg.CsrFilePath)
}

func ensureDirectoryExists(filePath string) error {
	if !util.FileDirExists(filePath) {
		logger.Warn("signCertificate", util.FileDir(filePath)+" directory not exists, creating...")
		if err := util.FileDirCreate(filePath); err != nil {
			return NewCertError("create directory", err)
		}
		logger.Info("signCertificate", util.FileDir(filePath)+" directory created")
	}
	return nil
}

// SignCertificate 根据证书类型签名证书
func SignCertificate(yamlPath string, certType CertificateType) (*x509.Certificate, error) {
	var cfg model.CAConfig
	if err := util.ReadYamlFileToStruct(yamlPath, &cfg); err != nil {
		return nil, NewCertError("read config file", err)
	}

	var cert model.Certificate
	switch certType {
	case CertTypeRoot:
		cert = cfg.CA.Root
	case CertTypeIntermediate:
		cert = cfg.CA.Intermediate
	case CertTypeServer:
		cert = cfg.CA.Server
	case CertTypeClient:
		cert = cfg.CA.Client
	default:
		return nil, ErrInvalidCertType
	}

	return signCertificate(cert)
}

// 为了保持向后兼容，保留原有的函数
func SignRootCertificate(yamlPath string) (*x509.Certificate, error) {
	return SignCertificate(yamlPath, CertTypeRoot)
}

func SignIntermediateCertificate(yamlPath string) (*x509.Certificate, error) {
	return SignCertificate(yamlPath, CertTypeIntermediate)
}

func SignServerCertificate(yamlPath string) (*x509.Certificate, error) {
	return SignCertificate(yamlPath, CertTypeServer)
}

func SignClientCertificate(yamlPath string) (*x509.Certificate, error) {
	return SignCertificate(yamlPath, CertTypeClient)
}
