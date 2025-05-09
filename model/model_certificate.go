package model

import (
	"crypto/x509"
)

type Certificate struct {
	Type         string `yaml:"type"`
	CertFilePath string `yaml:"cert"`
	KeyFilePath  string `yaml:"private_key"`
	CsrFilePath  string `yaml:"csr"`

	ParentCertPath string `yaml:"parent_cert"`
	ParentKeyPath  string `yaml:"parent_key"`
	ParentCert     *x509.Certificate
	ParentKey      interface{}

	IsCA          bool   `yaml:"is_ca"`
	Organization  string `yaml:"organization"`
	CommonName    string `yaml:"common_name"`
	ValidityYears int    `yaml:"validity_years"`
	ValidityMonth int    `yaml:"validity_month"`
	ValidityDay   int    `yaml:"validity_day"`
	KeyUsage      x509.KeyUsage
	ExtKeyUsage   []x509.ExtKeyUsage

	DNSNames    []string `yaml:"dns_names"`
	IPAddresses []string `yaml:"ip_addresses"`
	URIs        []string `yaml:"uris"`
}
