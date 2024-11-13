package certgo

import (
	"crypto/ecdsa"
	"os"
	"testing"
)

var testCases = []struct {
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
	for _, testCase := range testCases {
		actual, err := CreatePrivateKey(testCase.keyPath)
		if err != nil {
			t.Errorf("TestCreatePrivateKey: %v", err)
		}
		if actual == nil {
			t.Errorf("TestCreatePrivateKey: private key is nil")
		}
	}
}
