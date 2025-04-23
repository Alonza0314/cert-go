package main

import (
	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/constants"
	logger "github.com/Alonza0314/logger-go"
)

var privateKeyPath = "./private_key.pem"

func main() {
	logger.Info("CreatePrivateKey", "creating private key")

	if _, err := certgo.CreatePrivateKey(privateKeyPath, constants.PRIVATE_KEY_TYPE_ECDSA, true); err != nil {
		return
	}

	logger.Info("CreatePrivateKey", "private key created, you can see the private key in "+privateKeyPath)
}
