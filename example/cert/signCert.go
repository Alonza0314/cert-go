package main

import (
	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/logger"
)

var signCertYmlPath = "./signCertCfg.yml"

func main() {
	logger.Info("SignRootCertificate", "signing root certificate")

	certgo.SignRootCertificate(signCertYmlPath)

	logger.Info("SignRootCertificate", "root certificate signed, you can see the root certificate in ./root_cert.pem")
}
