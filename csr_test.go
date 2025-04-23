package certgo

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/Alonza0314/cert-go/constants"
	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
)

var testCaseCsr = []struct {
	name   string
	cfg    model.Certificate
	exist  bool
	force  bool
	expect *x509.CertificateRequest
}{
	{
		name: "test without exist",
		cfg: model.Certificate{
			KeyFilePath: "./default_ca/test.key.pem",
			CsrFilePath: "./default_ca/test.csr.pem",
		},
		exist: false,
		force: false,
	},
	{
		name: "test with exist and no force",
		cfg: model.Certificate{
			KeyFilePath: "./default_ca/test.key.pem",
			CsrFilePath: "./default_ca/test.csr.pem",
		},
		exist: true,
		force: false,
	},
	{
		name: "test with exist and force",
		cfg: model.Certificate{
			KeyFilePath: "./default_ca/test.key.pem",
			CsrFilePath: "./default_ca/test.csr.pem",
		},
		exist: true,
		force: true,
	},
}

func TestCreateCsrECDSA(t *testing.T) {
	var err error
	for _, testCase := range testCaseCsr {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.expect, err = CreateCsr(testCase.cfg, constants.PRIVATE_KEY_TYPE_ECDSA, testCase.force)
			if testCase.exist && !testCase.force {
				if err == nil || err.Error() != "csr already exists" {
					t.Fatalf("TestCreateCsrECDSA (%s): csr should exist and raise error", testCase.name)
				}
			} else {
				if err != nil {
					t.Fatalf("TestCreateCsrECDSA (%s): %v", testCase.name, err)
				}
				if testCase.expect == nil {
					t.Fatalf("TestCreateCsrECDSA (%s): csr is nil", testCase.name)
				}
				readCsr, err := util.ReadCsr(testCase.cfg.CsrFilePath)
				if err != nil {
					t.Fatalf("TestCreateCsrECDSA (%s): %v", testCase.name, err)
				}
				if readCsr == nil {
					t.Fatalf("TestCreateCsrECDSA (%s): read csr is nil", testCase.name)
				}
				if !reflect.DeepEqual(testCase.expect.Raw, readCsr.Raw) {
					t.Fatalf("TestCreateCsrECDSA (%s): csr content not equal", testCase.name)
				}
			}
		})
	}
	for _, testCase := range testCaseCsr {
		if !testCase.exist || testCase.force {
			if util.FileExists(testCase.cfg.KeyFilePath) {
				if err := util.FileDelete(testCase.cfg.KeyFilePath); err != nil {
					t.Fatalf("TestCreateCsrECDSA (%s): failed to delete key: %v", testCase.name, err)
				}
			}
			if util.FileExists(testCase.cfg.CsrFilePath) {
				if err := util.FileDelete(testCase.cfg.CsrFilePath); err != nil {
					t.Fatalf("TestCreateCsrECDSA (%s): failed to delete csr: %v", testCase.name, err)
				}
			}
		}
	}
}

func TestCreateCsrRSA(t *testing.T) {
	var err error
	for _, testCase := range testCaseCsr {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.expect, err = CreateCsr(testCase.cfg, constants.PRIVATE_KEY_TYPE_RSA, testCase.force)
			if testCase.exist && !testCase.force {
				if err == nil || err.Error() != "csr already exists" {
					t.Fatalf("TestCreateCsrRSA (%s): csr should exist and raise error", testCase.name)
				}
			} else {
				if err != nil {
					t.Fatalf("TestCreateCsrRSA (%s): %v", testCase.name, err)
				}
				if testCase.expect == nil {
					t.Fatalf("TestCreateCsrRSA (%s): csr is nil", testCase.name)
				}
				readCsr, err := util.ReadCsr(testCase.cfg.CsrFilePath)
				if err != nil {
					t.Fatalf("TestCreateCsrRSA (%s): %v", testCase.name, err)
				}
				if readCsr == nil {
					t.Fatalf("TestCreateCsrRSA (%s): read csr is nil", testCase.name)
				}
				if !reflect.DeepEqual(testCase.expect.Raw, readCsr.Raw) {
					t.Fatalf("TestCreateCsrRSA (%s): csr content not equal", testCase.name)
				}
			}
		})
	}
	for _, testCase := range testCaseCsr {
		if !testCase.exist || testCase.force {
			if util.FileExists(testCase.cfg.KeyFilePath) {
				if err := util.FileDelete(testCase.cfg.KeyFilePath); err != nil {
					t.Fatalf("TestCreateCsrRSA (%s): failed to delete key: %v", testCase.name, err)
				}
			}
			if util.FileExists(testCase.cfg.CsrFilePath) {
				if err := util.FileDelete(testCase.cfg.CsrFilePath); err != nil {
					t.Fatalf("TestCreateCsrRSA (%s): failed to delete csr: %v", testCase.name, err)
				}
			}
		}
	}
}
