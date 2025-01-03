package certgo

import (
	"crypto/ecdsa"
	"testing"

	"github.com/Alonza0314/cert-go/util"
)

var testCasePrivateKey = []struct {
	name    string
	keyPath string
	exist   bool
	expect  *ecdsa.PrivateKey
}{
	{
		name:    "test without exist",
		keyPath: "./default_ca/test.key.pem",
		exist:   false,
	},
	{
		name:    "test with exist",
		keyPath: "./default_ca/test.key.pem",
		exist:   true,
	},
}

func TestCreatePrivateKey(t *testing.T) {
	for _, testCase := range testCasePrivateKey {
		t.Run(testCase.name, func(t *testing.T) {
			privateKey, err := CreatePrivateKey(testCase.keyPath)
			if testCase.exist {
				if err == nil || err.Error() != "private key already exists" {
					t.Fatalf("TestCreatePrivateKey: private key should exist")
				}
			} else {
				if privateKey == nil {
					t.Fatalf("TestCreatePrivateKey: private key is nil")
				}
				readPrivateKey, err := util.ReadPrivateKey(testCase.keyPath)
				if err != nil {
					t.Fatalf("TestCreatePrivateKey: %v", err)
				}
				if readPrivateKey == nil {
					t.Fatalf("TestCreatePrivateKey: read private key is nil")
				}
				if privateKey.D.Cmp(readPrivateKey.D) != 0 {
					t.Fatalf("TestCreatePrivateKey: private key is not equal")
				}
			}
		})
	}
	for _, testCase := range testCasePrivateKey {
		if !testCase.exist {
			if err := util.FileDelete(testCase.keyPath); err != nil {
				t.Fatalf("TestCreatePrivateKey: %v", err)
			}
		}
	}
}
