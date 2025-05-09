package cmd

import (
	"strings"

	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/constants"
	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
	logger "github.com/Alonza0314/logger-go"
	"github.com/spf13/cobra"
)

var csrCmd = &cobra.Command{
	Use:   "csr",
	Short: "used to create csr",
	Long:  "used to create csr, you need to specify the configuration yaml file path",
	Run:   createCsr,
}

func init() {
	csrCmd.Flags().StringP("yaml", "y", "", "specify the configuration yaml file path")
	csrCmd.Flags().StringP("type", "t", "", "specify the type of the certificate: [intermediate, server, client]")
	csrCmd.Flags().BoolP("force", "f", false, "overwrite the csr if it already exists")
	csrCmd.Flags().StringP("key", "k", "", "specify the type of the private key, <ecdsa> or <rsa>")

	if err := csrCmd.MarkFlagRequired("yaml"); err != nil {
		logger.Error("cert-go", err.Error())
	}
	if err := csrCmd.MarkFlagRequired("type"); err != nil {
		logger.Error("cert-go", err.Error())
	}
	if err := csrCmd.MarkFlagRequired("key"); err != nil {
		logger.Error("cert-go", err.Error())
	}

	createCmd.AddCommand(csrCmd)
}

func createCsr(cmd *cobra.Command, args []string) {
	yamlPath, err := cmd.Flags().GetString("yaml")
	if err != nil {
		logger.Error("cert-go", err.Error())
		return
	}
	csrType, err := cmd.Flags().GetString("type")
	if err != nil {
		logger.Error("cert-go", err.Error())
		return
	}
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		logger.Error("cert-go", err.Error())
		return
	}
	keyType, err := cmd.Flags().GetString("key")
	if err != nil {
		logger.Error("cert-go", err.Error())
		return
	}

	var privateKeyType constants.PrivateKeyType
	if keyType == "rsa" {
		privateKeyType = constants.PRIVATE_KEY_TYPE_RSA
	} else {
		privateKeyType = constants.PRIVATE_KEY_TYPE_ECDSA
	}

	if csrType != string(constants.CERT_TYPE_INTERMEDIATE) && csrType != string(constants.CERT_TYPE_SERVER) && csrType != string(constants.CERT_TYPE_CLIENT) {
		logger.Error("cert-go", "invalid csr type, please specify the type of the certificate: [intermediate, server, client]")
		return
	}

	logger.Info("cert-go", "start to create csr")
	var cfg model.CAConfig
	if err := util.ReadYamlFileToStruct(yamlPath, &cfg); err != nil {
		logger.Error("cert-go", "failed to create csr")
		return
	}
	switch constants.CertType(csrType) {
	case constants.CERT_TYPE_INTERMEDIATE:
		_, err = certgo.CreateCsr(cfg.CA.Intermediate, privateKeyType, force)
	case constants.CERT_TYPE_SERVER:
		_, err = certgo.CreateCsr(cfg.CA.Server, privateKeyType, force)
	case constants.CERT_TYPE_CLIENT:
		_, err = certgo.CreateCsr(cfg.CA.Client, privateKeyType, force)
	}
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			logger.Error("cert-go", "use --force(f) to overwrite the csr")
		}
		logger.Error("cert-go", "failed to create csr")
		return
	}
	logger.Info("cert-go", "create csr success")
}
