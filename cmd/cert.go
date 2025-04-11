package cmd

import (
	certgo "github.com/Alonza0314/cert-go"
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

	if err := certCmd.MarkFlagRequired("yaml"); err != nil {
		logger.Error("cert-go", err.Error())
	}
	if err := certCmd.MarkFlagRequired("type"); err != nil {
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

	if certType != "root" && certType != "intermediate" && certType != "server" && certType != "client" {
		logger.Error("cert-go", "invalid cert type, please specify the type of the certificate: [root, intermediate, server, client]")
		return
	}

	logger.Info("cert-go", "start to create cert")
	switch certType {
	case "root":
		_, err = certgo.SignRootCertificate(yamlPath, force)
	case "intermediate":
		_, err = certgo.SignIntermediateCertificate(yamlPath, force)
	case "server":
		_, err = certgo.SignServerCertificate(yamlPath, force)
	case "client":
		_, err = certgo.SignClientCertificate(yamlPath, force)
	}
	if err != nil {
		logger.Error("cert-go", "failed to create cert")
		return
	}
	logger.Info("cert-go", "create cert success")
}
