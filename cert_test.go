package certgo

import (
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/Alonza0314/cert-go/util"
)

var testCaseCert = []struct {
	name     string
	yamlPath string
	certPath string
	expect   []byte
}{
	{
		name:     "root",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/root/root_cert.pem",
	},
	{
		name:     "intermediate",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/intermediate/intermediate_cert.pem",
	},
	{
		name:     "server",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/server/server_cert.pem",
	},
	{
		name:     "client",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/client/client_cert.pem",
	},
}

func TestSignCertificate(t *testing.T) {
	var err error
	for _, testCase := range testCaseCert {
		t.Run(testCase.name, func(t *testing.T) {
			switch testCase.name {
			case "root":
				testCase.expect, err = SignRootCertificate(testCase.yamlPath)
			case "intermediate":
				testCase.expect, err = SignIntermediateCertificate(testCase.yamlPath)
			case "server":
				testCase.expect, err = SignServerCertificate(testCase.yamlPath)
			case "client":
				testCase.expect, err = SignClientCertificate(testCase.yamlPath)
			}
			if err != nil {
				t.Fatalf("TestSignRootCertificate: %v", err)
			}

			readCert, err := util.ReadCertificate(testCase.certPath)
			if err != nil {
				t.Fatalf("TestSignRootCertificate: %v", err)
			}
			// parse expect to x509.Certificate
			block, _ := pem.Decode(testCase.expect)
			if block == nil {
				t.Fatalf("TestSignRootCertificate: failed to decode PEM block")
			}
			expectCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("TestSignRootCertificate: %v", err)
			}
			if !reflect.DeepEqual(expectCert, readCert) {
				t.Fatalf("TestSignRootCertificate: expect %v, but got %v", expectCert, readCert)
			}
		})
	}
}
