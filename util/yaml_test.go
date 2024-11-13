package util

import (
	"reflect"
	"testing"
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
					"cert":        "./default_ca/root/root_cert.pem",
					"private_key": "./default_ca/root/root_key.pem",
					"csr":         "./default_ca/root/root_csr.pem",
				},
				"intermediate": map[string]interface{}{
					"cert":        "./default_ca/intermediate/intermediate_cert.pem",
					"private_key": "./default_ca/intermediate/intermediate_key.pem",
					"csr":         "./default_ca/intermediate/intermediate_csr.pem",
				},
				"server": map[string]interface{}{
					"cert":        "./default_ca/server/server_cert.pem",
					"private_key": "./default_ca/server/server_key.pem",
					"csr":         "./default_ca/server/server_csr.pem",
				},
				"client": map[string]interface{}{
					"cert":        "./default_ca/client/client_cert.pem",
					"private_key": "./default_ca/client/client_key.pem",
					"csr":         "./default_ca/client/client_csr.pem",
				},
			},
		},
	},
}

func TestReadYamlFile(t *testing.T) {
	for _, testCase := range testCaseMap {
		data, err := ReadYamlFile(testCase.filePath)
		if err != nil {
			t.Errorf("TestReadYamlFile: %v", err)
		}
		if !reflect.DeepEqual(data, testCase.expect) {
			t.Errorf("TestReadYamlFile: actual %v != expect %v", data, testCase.expect)
		}
	}
}
