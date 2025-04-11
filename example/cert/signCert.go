package main

import (
	certgo "github.com/Alonza0314/cert-go"
	logger "github.com/Alonza0314/logger-go"
)

var signCertYmlPath = "./signCertCfg.yml"
var force = true

func main() {
	logger.Info("SignRootCertificate", "signing root certificate")

	if _, err := certgo.SignRootCertificate(signCertYmlPath, force); err != nil {
		return
	}

	logger.Info("SignRootCertificate", "root certificate signed, you can see the root certificate in ./root_cert.pem")
}
