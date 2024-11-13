package certgo

import (
	"crypto/x509"
	"os"
	"reflect"
	"testing"

	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
)

var testCaseCsr = []struct {
	cfg    model.Certificate
	expect *x509.CertificateRequest
}{
	{
		cfg: model.Certificate{
			KeyFilePath: "./test/test_key.pem",
			CsrFilePath: "./test/test_csr.pem",
		},
	},
}

func TestCreateCsr(t *testing.T) {
	if !util.FileExists("./test") {
		os.Mkdir("./test", 0775)
	}
	var err error
	for _, testCase := range testCaseCsr {
		t.Run(testCase.cfg.CsrFilePath, func(t *testing.T) {
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
