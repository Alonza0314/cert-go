package certgo

import (
	"crypto/ecdsa"
	"testing"

	"github.com/Alonza0314/cert-go/util"
)

var testCasePrivateKey = []struct {
	keyPath string
	expect  *ecdsa.PrivateKey
}{
	{
		keyPath: "./default_ca/test_key.pem",
	},
}

func TestCreatePrivateKey(t *testing.T) {
	for _, testCase := range testCasePrivateKey {
		t.Run(testCase.keyPath, func(t *testing.T) {
			privateKey, err := CreatePrivateKey(testCase.keyPath)
			if err != nil {
				t.Fatalf("TestCreatePrivateKey: %v", err)
			}
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
		})
	}
}
