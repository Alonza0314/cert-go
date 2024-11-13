package model

import (
	"crypto/ecdsa"
	"crypto/x509"
)

type CAConfig struct {
	CA CertificateAuthority `yaml:"ca"`
}

type CertificateAuthority struct {
	Root         Certificate `yaml:"root"`
	Intermediate Certificate `yaml:"intermediate"`
	Server       Certificate `yaml:"server"`
	Client       Certificate `yaml:"client"`
}

type Certificate struct {
	Type         string `yaml:"type"`
	CertFilePath string `yaml:"cert"`
	KeyFilePath  string `yaml:"private_key"`
	CsrFilePath  string `yaml:"csr"`

	ParentCertPath string `yaml:"parent_cert"`
	ParentKeyPath  string `yaml:"parent_key"`
	ParentCert     *x509.Certificate
	ParentKey      *ecdsa.PrivateKey

	IsCA          bool   `yaml:"is_ca"`
	Organization  string `yaml:"organization"`
	CommonName    string `yaml:"common_name"`
	ValidityYears int    `yaml:"validity_years"`
	ValidityMonth int    `yaml:"validity_month"`
	ValidityDay   int    `yaml:"validity_day"`
	KeyUsage      x509.KeyUsage
	ExtKeyUsage   []x509.ExtKeyUsage
}
