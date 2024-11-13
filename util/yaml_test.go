package util

import (
	"reflect"
	"testing"

	"github.com/Alonza0314/cert-go/model"
)

var testCaseMap = []struct {
	filePath string
	expect   map[string]interface{}
}{
	{
		filePath: "../cfg.yml",
		expect: map[string]interface{}{
			"ca": map[string]interface{}{
				"root": map[string]interface{}{
					"type":           "root",
					"cert":           "./default_ca/root/root_cert.pem",
					"private_key":    "./default_ca/root/root_key.pem",
					"csr":            "./default_ca/root/root_csr.pem",
					"is_ca":          true,
					"organization":   "default_ca",
					"common_name":    "default_ca",
					"validity_years": 10,
					"validity_month": 0,
					"validity_day":   0,
				},
				"intermediate": map[string]interface{}{
					"type":           "intermediate",
					"cert":           "./default_ca/intermediate/intermediate_cert.pem",
					"private_key":    "./default_ca/intermediate/intermediate_key.pem",
					"csr":            "./default_ca/intermediate/intermediate_csr.pem",
					"parent_cert":    "./default_ca/root/root_cert.pem",
					"parent_key":     "./default_ca/root/root_key.pem",
					"is_ca":          true,
					"organization":   "default_ca",
					"common_name":    "default_ca",
					"validity_years": 10,
					"validity_month": 0,
					"validity_day":   0,
				},
				"server": map[string]interface{}{
					"type":           "server",
					"cert":           "./default_ca/server/server_cert.pem",
					"private_key":    "./default_ca/server/server_key.pem",
					"csr":            "./default_ca/server/server_csr.pem",
					"parent_cert":    "./default_ca/intermediate/intermediate_cert.pem",
					"parent_key":     "./default_ca/intermediate/intermediate_key.pem",
					"is_ca":          false,
					"organization":   "default_ca",
					"common_name":    "default_ca",
					"validity_years": 10,
					"validity_month": 0,
					"validity_day":   0,
				},
				"client": map[string]interface{}{
					"type":           "client",
					"cert":           "./default_ca/client/client_cert.pem",
					"private_key":    "./default_ca/client/client_key.pem",
					"csr":            "./default_ca/client/client_csr.pem",
					"parent_cert":    "./default_ca/intermediate/intermediate_cert.pem",
					"parent_key":     "./default_ca/intermediate/intermediate_key.pem",
					"is_ca":          false,
					"organization":   "default_ca",
					"common_name":    "default_ca",
					"validity_years": 10,
					"validity_month": 0,
					"validity_day":   0,
				},
			},
		},
	},
}

var testCaseStruct = []struct {
	filePath string
	expect   model.CAConfig
}{
	{
		filePath: "../cfg.yml",
		expect: model.CAConfig{
			CA: model.CertificateAuthority{
				Root: model.Certificate{
					Type:          "root",
					CertFilePath:  "./default_ca/root/root_cert.pem",
					KeyFilePath:   "./default_ca/root/root_key.pem",
					CsrFilePath:   "./default_ca/root/root_csr.pem",
					IsCA:          true,
					Organization:  "default_ca",
					CommonName:    "default_ca",
					ValidityYears: 10,
					ValidityMonth: 0,
					ValidityDay:   0,
				},
				Intermediate: model.Certificate{
					Type:          "intermediate",
					CertFilePath:  "./default_ca/intermediate/intermediate_cert.pem",
					KeyFilePath:   "./default_ca/intermediate/intermediate_key.pem",
					CsrFilePath:   "./default_ca/intermediate/intermediate_csr.pem",
					ParentCertPath: "./default_ca/root/root_cert.pem",
					ParentKeyPath:  "./default_ca/root/root_key.pem",
					IsCA:           true,
					Organization:   "default_ca",
					CommonName:     "default_ca",
					ValidityYears:  10,
					ValidityMonth:  0,
					ValidityDay:    0,
				},
				Server: model.Certificate{
					Type:          "server",
					CertFilePath:  "./default_ca/server/server_cert.pem",
					KeyFilePath:   "./default_ca/server/server_key.pem",
					CsrFilePath:   "./default_ca/server/server_csr.pem",
					ParentCertPath: "./default_ca/intermediate/intermediate_cert.pem",
					ParentKeyPath:  "./default_ca/intermediate/intermediate_key.pem",
					IsCA:           false,
					Organization:   "default_ca",
					CommonName:     "default_ca",
					ValidityYears:  10,
					ValidityMonth:  0,
					ValidityDay:    0,
				},
				Client: model.Certificate{
					Type:          "client",
					CertFilePath:  "./default_ca/client/client_cert.pem",
					KeyFilePath:    "./default_ca/client/client_key.pem",
					CsrFilePath:    "./default_ca/client/client_csr.pem",
					ParentCertPath: "./default_ca/intermediate/intermediate_cert.pem",
					ParentKeyPath:  "./default_ca/intermediate/intermediate_key.pem",
					IsCA:           false,
					Organization:   "default_ca",
					CommonName:     "default_ca",
					ValidityYears:  10,
					ValidityMonth:  0,
					ValidityDay:    0,
				},
			},
		},
	},
}

func TestReadYamlFile(t *testing.T) {
	for _, testCase := range testCaseMap {
		t.Run(testCase.filePath, func(t *testing.T) {
			data, err := ReadYamlFile(testCase.filePath)
			if err != nil {
				t.Errorf("TestReadYamlFile: %v", err)
			}
			if !reflect.DeepEqual(data, testCase.expect) {
				t.Errorf("TestReadYamlFile: actual %v != expect %v", data, testCase.expect)
			}
		})
	}
}

func TestReadYamlFileToStruct(t *testing.T) {
	for _, testCase := range testCaseStruct {
		t.Run(testCase.filePath, func(t *testing.T) {
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
