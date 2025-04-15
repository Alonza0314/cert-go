package certgo

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
)

var testCaseCsr = []struct {
	name   string
	cfg    model.Certificate
	exist  bool
	expect *x509.CertificateRequest
}{
	{
		name: "test without exist",
		cfg: model.Certificate{
			KeyFilePath: "./default_ca/test.key.pem",
			CsrFilePath: "./default_ca/test.csr.pem",
		},
		exist:  false,
	},
	{
		name: "test with exist",
		cfg: model.Certificate{
			KeyFilePath: "./default_ca/test.key.pem",
			CsrFilePath: "./default_ca/test.csr.pem",
		},
		exist:  true,
	},
}

func TestCreateCsr(t *testing.T) {
	var err error
	for _, testCase := range testCaseCsr {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.expect, err = CreateCsr(testCase.cfg)
			if testCase.exist {
				if err == nil || err.Error() != "csr already exists" {
					t.Fatalf("TestCreateCsr: csr should exist")
				}
			} else {
				if err != nil {
					t.Fatalf("TestCreateCsr: %v", err)
				}
				if testCase.expect == nil {
					t.Fatalf("TestCreateCsr: csr is nil")
				}
				readCsr, err := util.ReadCsr(testCase.cfg.CsrFilePath)
				if err != nil {
					t.Fatalf("TestCreateCsr: %v", err)
				}
				if readCsr == nil {
					t.Fatalf("TestCreateCsr: read csr is nil")
				}
				if !reflect.DeepEqual(testCase.expect, readCsr) {
					t.Fatalf("TestCreateCsr: csr is not equal")
				}
			}
		})
	}
	for _, testCase := range testCaseCsr {
		if !testCase.exist {
			if err := util.FileDelete(testCase.cfg.KeyFilePath); err != nil {
				t.Fatalf("TestCreateCsr: %v", err)
			}
			if err := util.FileDelete(testCase.cfg.CsrFilePath); err != nil {
				t.Fatalf("TestCreateCsr: %v", err)
			}
		}
	}
}
