package main

import (
	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/constants"
	logger "github.com/Alonza0314/logger-go"
)

var signCertYmlPath = "./signCertCfg.yml"

func main() {
	logger.Info("SignCertificate", "signing root certificate")

	if _, err := certgo.SignCertificate(constants.CERT_TYPE_ROOT, constants.PRIVATE_KEY_TYPE_ECDSA, signCertYmlPath, true); err != nil {
		return
	}

	logger.Info("SignCertificate", "root certificate signed, you can see the certificate in ./root_cert.pem")
}
