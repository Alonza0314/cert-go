package util

import (
	"reflect"
	"testing"

	"github.com/Alonza0314/cert-go/model"
)

var testCaseStruct = []struct {
	name     string
	filePath string
	expect   model.CAConfig
}{
	{
		name:     "testStruct",
		filePath: "../defaultCfg.yml",
		expect: model.CAConfig{
			CA: model.CertificateAuthority{
				Root: model.Certificate{
					Type:          "root",
					CertFilePath:  "./default_ca/root/root.cert.pem",
					KeyFilePath:   "./default_ca/root/root.key.pem",
					IsCA:          true,
					Organization:  "default_ca",
					CommonName:    "default_ca",
					ValidityYears: 10,
					ValidityMonth: 0,
					ValidityDay:   0,
				},
				Intermediate: model.Certificate{
					Type:           "intermediate",
					CertFilePath:   "./default_ca/intermediate/intermediate.cert.pem",
					KeyFilePath:    "./default_ca/intermediate/intermediate.key.pem",
					CsrFilePath:    "./default_ca/intermediate/intermediate.csr.pem",
					ParentCertPath: "./default_ca/root/root.cert.pem",
					ParentKeyPath:  "./default_ca/root/root.key.pem",
					IsCA:           true,
					Organization:   "default_ca",
					CommonName:     "default_ca",
					ValidityYears:  10,
					ValidityMonth:  0,
					ValidityDay:    0,
				},
				Server: model.Certificate{
					Type:           "server",
					CertFilePath:   "./default_ca/server/server.cert.pem",
					KeyFilePath:    "./default_ca/server/server.key.pem",
					CsrFilePath:    "./default_ca/server/server.csr.pem",
					ParentCertPath: "./default_ca/intermediate/intermediate.cert.pem",
					ParentKeyPath:  "./default_ca/intermediate/intermediate.key.pem",
					IsCA:           false,
					Organization:   "default_ca",
					CommonName:     "default_ca",
					ValidityYears:  10,
					ValidityMonth:  0,
					ValidityDay:    0,
					DNSNames:       []string{"localhost"},
					IPAddresses:    []string{"127.0.0.1", "0.0.0.0"},
					URIs:           []string{},
				},
				Client: model.Certificate{
					Type:           "client",
					CertFilePath:   "./default_ca/client/client.cert.pem",
					KeyFilePath:    "./default_ca/client/client.key.pem",
					CsrFilePath:    "./default_ca/client/client.csr.pem",
					ParentCertPath: "./default_ca/intermediate/intermediate.cert.pem",
					ParentKeyPath:  "./default_ca/intermediate/intermediate.key.pem",
					IsCA:           false,
					Organization:   "default_ca",
					CommonName:     "default_ca",
					ValidityYears:  10,
					ValidityMonth:  0,
					ValidityDay:    0,
					DNSNames:       []string{"localhost"},
					IPAddresses:    []string{"127.0.0.1", "0.0.0.0"},
					URIs:           []string{},
				},
			},
		},
	},
}

func TestReadYamlFileToStruct(t *testing.T) {
	for _, testCase := range testCaseStruct {
		t.Run(testCase.name, func(t *testing.T) {
			var actual model.CAConfig
			err := ReadYamlFileToStruct(testCase.filePath, &actual)
			if err != nil {
				t.Errorf("TestReadYamlFileToStruct: %v", err)
			}
			if !reflect.DeepEqual(actual, testCase.expect) {
				t.Errorf("TestReadYamlFileToStruct: actual %v != expect %v", actual, testCase.expect)
			}
		})
	}
}
