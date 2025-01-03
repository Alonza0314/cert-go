package certgo

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/Alonza0314/cert-go/util"
)

var testCaseCert = []struct {
	name     string
	yamlPath string
	certPath string
	exist    bool
	expect   *x509.Certificate
}{
	{
		name:     "root without exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/root/root.cert.pem",
		exist:    false,
	},
	{
		name:     "root with exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/root/root.cert.pem",
		exist:    true,
	},
	{
		name:     "intermediate without exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/intermediate/intermediate.cert.pem",
		exist:    false,
	},
	{
		name:     "intermediate with exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/intermediate/intermediate.cert.pem",
		exist:    true,
	},
	{
		name:     "server without exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/server/server.cert.pem",
		exist:    false,
	},
	{
		name:     "server with exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/server/server.cert.pem",
		exist:    true,
	},
	{
		name:     "client without exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/client/client.cert.pem",
		exist:    false,
	},
	{
		name:     "client with exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/client/client.cert.pem",
		exist:    true,
	},
}

func TestSignCertificate(t *testing.T) {
	var err error
	for _, testCase := range testCaseCert {
		t.Run(testCase.name, func(t *testing.T) {
			switch testCase.name {
			case "root without exist", "root with exist":
				testCase.expect, err = SignRootCertificate(testCase.yamlPath)
			case "intermediate without exist", "intermediate with exist":
				testCase.expect, err = SignIntermediateCertificate(testCase.yamlPath)
			case "server without exist", "server with exist":
				testCase.expect, err = SignServerCertificate(testCase.yamlPath)
			case "client without exist", "client with exist":
				testCase.expect, err = SignClientCertificate(testCase.yamlPath)
			}
			if testCase.exist {
				if err == nil || err.Error() != "certificate already exists" {
					t.Fatalf("TestSignRootCertificate: certificate should exist")
				}
			} else {
				if err != nil {
					t.Fatalf("TestSignRootCertificate: %v", err)
				}
				if testCase.expect == nil {
					t.Fatalf("TestSignRootCertificate: certificate is nil")
				}
				readCert, err := util.ReadCertificate(testCase.certPath)
				if err != nil {
					t.Fatalf("TestSignRootCertificate: %v", err)
				}
				if readCert == nil {
					t.Fatalf("TestSignRootCertificate: read certificate is nil")
				}
				if !reflect.DeepEqual(testCase.expect, readCert) {
					t.Fatalf("TestSignRootCertificate: certificate is not equal")
				}
			}
		})
	}
}
