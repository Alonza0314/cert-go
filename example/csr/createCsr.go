package main

import (
	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/constants"
	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
	logger "github.com/Alonza0314/logger-go"
)

var createCsrYmlPath = "./createCsrCfg.yml"

func main() {
	var cfg model.CAConfig
	if err := util.ReadYamlFileToStruct(createCsrYmlPath, &cfg); err != nil {
		return
	}

	logger.Info("CreateCsr", "creating csr")
	if _, err := certgo.CreateCsr(cfg.CA.Intermediate, constants.PRIVATE_KEY_TYPE_ECDSA, true); err != nil {
		return
	}

	logger.Info("CreateCsr", "csr created, you can see the csr in ./intermediate_csr.pem")
}
