package main

import (
	certgo "github.com/Alonza0314/cert-go"
	logger "github.com/Alonza0314/logger-go"
)

var privateKeyPath = "./private_key.pem"
var force = true

func main() {
	logger.Info("CreatePrivateKey", "creating private key")

	if _, err := certgo.CreatePrivateKey(privateKeyPath, force); err != nil {
		return
	}

	logger.Info("CreatePrivateKey", "private key created, you can see the private key in "+privateKeyPath)
}
