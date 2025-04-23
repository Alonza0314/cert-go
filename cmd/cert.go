package cmd

import (
	"strings"

	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/constants"
	logger "github.com/Alonza0314/logger-go"
	"github.com/spf13/cobra"
)

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "used to create certificate",
	Long:  "used to create certificate, you need to specify the configuration yaml file path",
	Run:   createCert,
}

func init() {
	certCmd.Flags().StringP("yaml", "y", "", "specify the configuration yaml file path")
	certCmd.Flags().StringP("type", "t", "", "specify the type of the certificate: [root, intermediate, server, client]")
	certCmd.Flags().BoolP("force", "f", false, "overwrite the certificate if it already exists")
	certCmd.Flags().StringP("key", "k", "", "specify the type of the private key, <ecdsa> or <rsa>")

	if err := certCmd.MarkFlagRequired("yaml"); err != nil {
		logger.Error("cert-go", err.Error())
	}
	if err := certCmd.MarkFlagRequired("type"); err != nil {
		logger.Error("cert-go", err.Error())
	}
	if err := certCmd.MarkFlagRequired("key"); err != nil {
		logger.Error("cert-go", err.Error())
	}

	createCmd.AddCommand(certCmd)
}

func createCert(cmd *cobra.Command, args []string) {
	yamlPath, err := cmd.Flags().GetString("yaml")
	if err != nil {
		logger.Error("cert-go", err.Error())
		return
	}
	certType, err := cmd.Flags().GetString("type")
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

	if certType != string(constants.CERT_TYPE_ROOT) && certType != string(constants.CERT_TYPE_INTERMEDIATE) && certType != string(constants.CERT_TYPE_SERVER) && certType != string(constants.CERT_TYPE_CLIENT) {
		logger.Error("cert-go", "invalid cert type, please specify the type of the certificate: [root, intermediate, server, client]")
		return
	}

	logger.Info("cert-go", "start to create cert")
	switch constants.CertType(certType) {
	case constants.CERT_TYPE_ROOT:
		_, err = certgo.SignCertificate(constants.CERT_TYPE_ROOT, privateKeyType, yamlPath, force)
	case constants.CERT_TYPE_INTERMEDIATE:
		_, err = certgo.SignCertificate(constants.CERT_TYPE_INTERMEDIATE, privateKeyType, yamlPath, force)
	case constants.CERT_TYPE_SERVER:
		_, err = certgo.SignCertificate(constants.CERT_TYPE_SERVER, privateKeyType, yamlPath, force)
	case constants.CERT_TYPE_CLIENT:
		_, err = certgo.SignCertificate(constants.CERT_TYPE_CLIENT, privateKeyType, yamlPath, force)
	}
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			logger.Error("cert-go", "use --force(f) to overwrite the cert")
		}
		logger.Error("cert-go", "failed to create cert")
		return
	}
	logger.Info("cert-go", "create cert success")
}
