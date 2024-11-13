package model

import (
	"crypto/ecdsa"
	"crypto/x509"
)

type Certificate struct {
	Type         string
	CertFilePath string
	KeyFilePath  string
	CsrFilePath  string

	ParentCert    *x509.Certificate
	ParentKey     *ecdsa.PrivateKey
	IsCA          bool
	Organization  string
	CommonName    string
	ValidityYears int
	KeyUsage      x509.KeyUsage
	ExtKeyUsage   []x509.ExtKeyUsage
}
