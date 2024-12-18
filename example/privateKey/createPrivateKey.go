package main

import (
	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/logger"
)

var privateKeyPath = "./private_key.pem"

func main() {
	logger.Info("CreatePrivateKey", "creating private key")

	if _, err := certgo.CreatePrivateKey(privateKeyPath); err != nil {
		return
	}

	logger.Info("CreatePrivateKey", "private key created, you can see the private key in "+privateKeyPath)
}
