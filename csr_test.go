package certgo

import (
	"bytes"
	"os"
	"testing"

	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
)

var testCaseCsr = []struct {
	cfg    model.Certificate
	expect []byte
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
	for _, testCase := range testCaseCsr {
		csr, err := CreateCsr(testCase.cfg)
		if err != nil {
			t.Errorf("TestCreateCsr: %v", err)
		}
		if csr == nil {
			t.Errorf("TestCreateCsr: csr is nil")
		}
		readCsr, err := util.ReadCsr(testCase.cfg.CsrFilePath)
		if err != nil {
			t.Errorf("TestCreateCsr: %v", err)
		}
		if readCsr == nil {
			t.Errorf("TestCreateCsr: read csr is nil")
		}
		if !bytes.Equal(csr, readCsr) {
			t.Errorf("TestCreateCsr: csr is not equal")
		}
	}
}
