package certgo

import (
	"crypto/ecdsa"
	"os"
	"testing"

	"github.com/Alonza0314/cert-go/util"
)

var testCasePrivateKey = []struct {
	keyPath string
	expect  *ecdsa.PrivateKey
}{
	{
		keyPath: "./test/test_key.pem",
	},
}

func TestCreatePrivateKey(t *testing.T) {
	if _, err := os.Stat("./test"); os.IsNotExist(err) {
		os.Mkdir("./test", 0775)
	}
	for _, testCase := range testCasePrivateKey {
		privateKey, err := CreatePrivateKey(testCase.keyPath)
		if err != nil {
			t.Errorf("TestCreatePrivateKey: %v", err)
		}
		if privateKey == nil {
			t.Errorf("TestCreatePrivateKey: private key is nil")
		}
		readPrivateKey, err := util.ReadPrivateKey(testCase.keyPath)
		if err != nil {
			t.Errorf("TestCreatePrivateKey: %v", err)
		}
		if readPrivateKey == nil {
			t.Errorf("TestCreatePrivateKey: read private key is nil")
		}
		if privateKey.D.Cmp(readPrivateKey.D) != 0 {
			t.Errorf("TestCreatePrivateKey: private key is not equal")
		}
	}
}
