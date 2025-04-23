package certgo

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/Alonza0314/cert-go/constants"
	"github.com/Alonza0314/cert-go/util"
)

var testCasePrivateKey = []struct {
	name    string
	keyPath string
	exist   bool
	force   bool
	expect  interface{}
}{
	{
		name:    "test without exist",
		keyPath: "./default_ca/test.key.pem",
		exist:   false,
		force:   false,
	},
	{
		name:    "test with exist and no force",
		keyPath: "./default_ca/test.key.pem",
		exist:   true,
		force:   false,
	},
	{
		name:    "test with exist and force",
		keyPath: "./default_ca/test.key.pem",
		exist:   true,
		force:   true,
	},
}

func TestCreatePrivateKeyECDSA(t *testing.T) {
	for _, testCase := range testCasePrivateKey {
		t.Run(testCase.name, func(t *testing.T) {
			privateKey, err := CreatePrivateKey(testCase.keyPath, constants.PRIVATE_KEY_TYPE_ECDSA, testCase.force)
			if testCase.exist && !testCase.force {
				if err == nil || err.Error() != "private key already exists" {
					t.Fatalf("TestCreatePrivateKeyECDSA: private key should exist")
				}
			} else {
				if privateKey == nil {
					t.Fatalf("TestCreatePrivateKeyECDSA: private key is nil")
				}
				readPrivateKey, err := util.ReadPrivateKey(testCase.keyPath)
				if err != nil {
					t.Fatalf("TestCreatePrivateKeyECDSA: %v", err)
				}
				if readPrivateKey == nil {
					t.Fatalf("TestCreatePrivateKeyECDSA: read private key is nil")
				}
				if privateKey.(*ecdsa.PrivateKey).D.Cmp(readPrivateKey.(*ecdsa.PrivateKey).D) != 0 {
					t.Fatalf("TestCreatePrivateKeyECDSA: private key is not equal")
				}
			}
		})
	}
	for _, testCase := range testCasePrivateKey {
		if !testCase.exist || testCase.force {
			if util.FileExists(testCase.keyPath) {
				if err := util.FileDelete(testCase.keyPath); err != nil {
					t.Fatalf("TestCreatePrivateKeyECDSA (%s): failed to delete key: %v", testCase.name, err)
				}
			}
		}
	}
}

func TestCreatePrivateKeyRSA(t *testing.T) {
	for _, testCase := range testCasePrivateKey {
		t.Run(testCase.name, func(t *testing.T) {
			privateKey, err := CreatePrivateKey(testCase.keyPath, constants.PRIVATE_KEY_TYPE_RSA, testCase.force)
			if testCase.exist && !testCase.force {
				if err == nil || err.Error() != "private key already exists" {
					t.Fatalf("TestCreatePrivateKeyRSA: private key should exist")
				}
			} else {
				if privateKey == nil {
					t.Fatalf("TestCreatePrivateKeyRSA: private key is nil")
				}
				readPrivateKey, err := util.ReadPrivateKey(testCase.keyPath)
				if err != nil {
					t.Fatalf("TestCreatePrivateKeyRSA: %v", err)
				}
				if readPrivateKey == nil {
					t.Fatalf("TestCreatePrivateKeyRSA: read private key is nil")
				}
				if privateKey.(*rsa.PrivateKey).D.Cmp(readPrivateKey.(*rsa.PrivateKey).D) != 0 {
					t.Fatalf("TestCreatePrivateKeyRSA: private key is not equal")
				}
			}
		})
	}
	for _, testCase := range testCasePrivateKey {
		if !testCase.exist || testCase.force {
			if util.FileExists(testCase.keyPath) {
				if err := util.FileDelete(testCase.keyPath); err != nil {
					t.Fatalf("TestCreatePrivateKeyRSA (%s): failed to delete key: %v", testCase.name, err)
				}
			}
		}
	}
}
