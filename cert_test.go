package certgo

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/Alonza0314/cert-go/constants"
	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
)

var testCaseCreateCert = []struct {
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

func TestSignCertificateECDSA(t *testing.T) {
	var err error
	for _, testCase := range testCaseCreateCert {
		t.Run(testCase.name, func(t *testing.T) {
			switch testCase.name {
			case "root without exist", "root with exist and no force", "root with exist and force":
				testCase.expect, err = SignCertificate(constants.CERT_TYPE_ROOT, constants.PRIVATE_KEY_TYPE_ECDSA, testCase.yamlPath, testCase.force)
			case "intermediate without exist", "intermediate with exist and no force", "intermediate with exist and force":
				testCase.expect, err = SignCertificate(constants.CERT_TYPE_INTERMEDIATE, constants.PRIVATE_KEY_TYPE_ECDSA, testCase.yamlPath, testCase.force)
			case "server without exist", "server with exist and no force", "server with exist and force":
				testCase.expect, err = SignCertificate(constants.CERT_TYPE_SERVER, constants.PRIVATE_KEY_TYPE_ECDSA, testCase.yamlPath, testCase.force)
			case "client without exist", "client with exist and no force", "client with exist and force":
				testCase.expect, err = SignCertificate(constants.CERT_TYPE_CLIENT, constants.PRIVATE_KEY_TYPE_ECDSA, testCase.yamlPath, testCase.force)
			}
			if testCase.exist && !testCase.force {
				if err == nil || err.Error() != "certificate already exists" {
					t.Fatalf("TestSignCertificateECDSA (%s): expected error for existing certificate without force", testCase.name)
				}
			} else {
				if err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
				if testCase.expect == nil {
					t.Fatalf("TestSignCertificateECDSA: certificate is nil")
				}
				readCert, err := util.ReadCertificate(testCase.certPath)
				if err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
				if readCert == nil {
					t.Fatalf("TestSignCertificateECDSA: read certificate is nil")
				}
				if !reflect.DeepEqual(testCase.expect, readCert) {
					t.Fatalf("TestSignCertificateECDSA: certificate is not equal")
				}
			}
		})
	}
	for _, testCase := range testCaseCreateCert {
		if !testCase.exist {
			var cfg model.CAConfig
			if err := util.ReadYamlFileToStruct(testCase.yamlPath, &cfg); err != nil {
				t.Fatalf("TestSignCertificateECDSA: %v", err)
			}
			switch testCase.name {
			case "root without exist":
				if err := util.FileDelete(cfg.CA.Root.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Root.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
			case "intermediate without exist":
				if err := util.FileDelete(cfg.CA.Intermediate.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Intermediate.CsrFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Intermediate.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
			case "server without exist":
				if err := util.FileDelete(cfg.CA.Server.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Server.CsrFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Server.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
			case "client without exist":
				if err := util.FileDelete(cfg.CA.Client.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Client.CsrFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Client.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificateECDSA: %v", err)
				}
			}
		}
	}
}

func TestSignCertificateRSA(t *testing.T) {
	var err error
	for _, testCase := range testCaseCreateCert {
		t.Run(testCase.name, func(t *testing.T) {
			switch testCase.name {
			case "root without exist", "root with exist and no force", "root with exist and force":
				testCase.expect, err = SignCertificate(constants.CERT_TYPE_ROOT, constants.PRIVATE_KEY_TYPE_RSA, testCase.yamlPath, testCase.force)
			case "intermediate without exist", "intermediate with exist and no force", "intermediate with exist and force":
				testCase.expect, err = SignCertificate(constants.CERT_TYPE_INTERMEDIATE, constants.PRIVATE_KEY_TYPE_RSA, testCase.yamlPath, testCase.force)
			case "server without exist", "server with exist and no force", "server with exist and force":
				testCase.expect, err = SignCertificate(constants.CERT_TYPE_SERVER, constants.PRIVATE_KEY_TYPE_RSA, testCase.yamlPath, testCase.force)
			case "client without exist", "client with exist and no force", "client with exist and force":
				testCase.expect, err = SignCertificate(constants.CERT_TYPE_CLIENT, constants.PRIVATE_KEY_TYPE_RSA, testCase.yamlPath, testCase.force)
			}
			if testCase.exist && !testCase.force {
				if err == nil || err.Error() != "certificate already exists" {
					t.Fatalf("TestSignCertificateRSA (%s): expected error for existing certificate without force", testCase.name)
				}
			} else {
				if err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
				if testCase.expect == nil {
					t.Fatalf("TestSignCertificateRSA: certificate is nil")
				}
				readCert, err := util.ReadCertificate(testCase.certPath)
				if err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
				if readCert == nil {
					t.Fatalf("TestSignCertificateRSA: read certificate is nil")
				}
				if !reflect.DeepEqual(testCase.expect, readCert) {
					t.Fatalf("TestSignCertificateRSA: certificate is not equal")
				}
			}
		})
	}
	for _, testCase := range testCaseCreateCert {
		if !testCase.exist {
			var cfg model.CAConfig
			if err := util.ReadYamlFileToStruct(testCase.yamlPath, &cfg); err != nil {
				t.Fatalf("TestSignCertificateRSA: %v", err)
			}
			switch testCase.name {
			case "root without exist":
				if err := util.FileDelete(cfg.CA.Root.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Root.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
			case "intermediate without exist":
				if err := util.FileDelete(cfg.CA.Intermediate.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Intermediate.CsrFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Intermediate.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
			case "server without exist":
				if err := util.FileDelete(cfg.CA.Server.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Server.CsrFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Server.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
			case "client without exist":
				if err := util.FileDelete(cfg.CA.Client.CertFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Client.CsrFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
				if err := util.FileDelete(cfg.CA.Client.KeyFilePath); err != nil {
					t.Fatalf("TestSignCertificateRSA: %v", err)
				}
			}
		}
	}
}

var testCaseCreateCertKeyTypeUnderRSA = []struct {
	name string
	cfg model.Certificate
	keyType constants.PrivateKeyType
	errFlag bool
}{
	{
		name: "test with ecdsa key type",
		keyType: constants.PRIVATE_KEY_TYPE_ECDSA,
		errFlag: true,
	},
	{
		name: "test with rsa key type",
		keyType: constants.PRIVATE_KEY_TYPE_RSA,
		errFlag: false,
	},
}

func TestCreateCertKeyTypeUnderRSA(t *testing.T) {
	yamlPath := "./defaultCfg.yml"
	cfg := model.CAConfig{}
	if err := util.ReadYamlFileToStruct(yamlPath, &cfg); err != nil {
		t.Fatalf("TestCreateCertKeyTypeUnderRSA: %v", err)
	}
	
	if _, err := CreatePrivateKey(cfg.CA.Root.KeyFilePath, constants.PRIVATE_KEY_TYPE_RSA, false); err != nil {
		t.Fatalf("TestCreateCertKeyTypeUnderRSA: %v", err)
	}

	for _, testCase := range testCaseCreateCertKeyTypeUnderRSA {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := SignCertificate(constants.CERT_TYPE_ROOT, testCase.keyType, yamlPath, false)
			if testCase.errFlag {
				if err == nil {
					t.Fatalf("TestCreateCertKeyTypeUnderRSA (%s): error should be raised", testCase.name)
				}
				if err.Error() != "private key type: RSA is not same as the specified key type: ECDSA" {
					t.Fatalf("TestCreateCertKeyTypeUnderRSA (%s): error should be 'private key type: RSA is not same as the specified key type: ECDSA' but got '%s'", testCase.name, err.Error())
				}
			}
		})
	}

	if err := util.FileDelete(cfg.CA.Root.KeyFilePath); err != nil {
		t.Fatalf("TestCreateCertKeyTypeUnderRSA: %v", err)
	}
	if err := util.FileDelete(cfg.CA.Root.CertFilePath); err != nil {
		t.Fatalf("TestCreateCertKeyTypeUnderRSA: %v", err)
	}
}