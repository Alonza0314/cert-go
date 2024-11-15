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
	expect *x509.CertificateRequest
}{
	{
		name: "test",
		cfg: model.Certificate{
			KeyFilePath: "./default_ca/test.key.pem",
			CsrFilePath: "./default_ca/test.csr.pem",
		},
	},
}

func TestCreateCsr(t *testing.T) {
	var err error
	for _, testCase := range testCaseCsr {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.expect, err = CreateCsr(testCase.cfg)
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
		})
	}
}
