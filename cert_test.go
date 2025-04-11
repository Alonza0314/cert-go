package certgo

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
)

var testCaseCert = []struct {
	name     string
	yamlPath string
	certPath string
	exist    bool
	force    bool
	expect   *x509.Certificate
}{
	{
		name:     "root without exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/root/root.cert.pem",
		exist:    false,
		force:    false,
	},
	{
		name:     "root with exist and no force",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/root/root.cert.pem",
		exist:    true,
		force:    false,
	},
	{
		name:     "root with exist and force",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/root/root.cert.pem",
		exist:    true,
		force:    true,
	},
	{
		name:     "intermediate without exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/intermediate/intermediate.cert.pem",
		exist:    false,
		force:    false,
	},
	{
		name:     "intermediate with exist and no force",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/intermediate/intermediate.cert.pem",
		exist:    true,
		force:    false,
	},
	{
		name:     "intermediate with exist and force",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/intermediate/intermediate.cert.pem",
		exist:    true,
		force:    true,
	},
	{
		name:     "server without exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/server/server.cert.pem",
		exist:    false,
		force:    false,
	},
	{
		name:     "server with exist and no force",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/server/server.cert.pem",
		exist:    true,
		force:    false,
	},
	{
		name:     "server with exist and force",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/server/server.cert.pem",
		exist:    true,
		force:    true,
	},
	{
		name:     "client without exist",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/client/client.cert.pem",
		exist:    false,
		force:    false,
	},
	{
		name:     "client with exist and no force",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/client/client.cert.pem",
		exist:    true,
		force:    false,
	},
	{
		name:     "client with exist and force",
		yamlPath: "./defaultCfg.yml",
		certPath: "./default_ca/client/client.cert.pem",
		exist:    true,
		force:    true,
	},
}

func TestSignCertificate(t *testing.T) {
	var err error
	for _, testCase := range testCaseCert {
		t.Run(testCase.name, func(t *testing.T) {
			switch testCase.name {
			case "root without exist", "root with exist and no force", "root with exist and force":
				testCase.expect, err = SignRootCertificate(testCase.yamlPath, testCase.force)
			case "intermediate without exist", "intermediate with exist and no force", "intermediate with exist and force":
				testCase.expect, err = SignIntermediateCertificate(testCase.yamlPath, testCase.force)
			case "server without exist", "server with exist and no force", "server with exist and force":
				testCase.expect, err = SignServerCertificate(testCase.yamlPath, testCase.force)
			case "client without exist", "client with exist and no force", "client with exist and force":
				testCase.expect, err = SignClientCertificate(testCase.yamlPath, testCase.force)
			}
			if testCase.exist && !testCase.force{
				if err == nil || err.Error() != "certificate already exists" {
					t.Fatalf("TestSignCertificate (%s): expected error for existing certificate without force", testCase.name)	
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
	for _, testCase := range testCaseCert {
		if !testCase.exist {
			var cfg model.CAConfig
			if err := util.ReadYamlFileToStruct(testCase.yamlPath, &cfg); err != nil {
				t.Fatalf("TestSignCertificate: %v", err)
			}
			switch testCase.name {
			case "root without exist":
				if err := util.FileDelete(cfg.CA.Root.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Root.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
			case "intermediate without exist":
				if err := util.FileDelete(cfg.CA.Intermediate.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Intermediate.CsrFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Intermediate.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
			case "server without exist":
				if err := util.FileDelete(cfg.CA.Server.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Server.CsrFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Server.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
			case "client without exist":
				if err := util.FileDelete(cfg.CA.Client.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Client.CsrFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Client.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificate: %v", err)
				}
			}
		}
	}
}
