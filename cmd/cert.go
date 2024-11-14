package cmd

import (
	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/logger"
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
	certCmd.MarkFlagRequired("yaml")
	certCmd.MarkFlagRequired("type")

	createCmd.AddCommand(certCmd)
}

func createCert(cmd *cobra.Command, args []string) {
	yamlPath, err := cmd.Flags().GetString("yaml")
	if err != nil {
		logger.Error("CMD", err.Error())
		return
	}
	certType, err := cmd.Flags().GetString("type")
	if err != nil {
		logger.Error("CMD", err.Error())
		return
	}

	if certType != "root" && certType != "intermediate" && certType != "server" && certType != "client" {
		logger.Error("CMD", "invalid cert type, please specify the type of the certificate: [root, intermediate, server, client]")
		return
	}

	logger.Info("CMD", "start to create cert")
	switch certType {
	case "root":
		_, err = certgo.SignRootCertificate(yamlPath)
	case "intermediate":
		_, err = certgo.SignIntermediateCertificate(yamlPath)
	case "server":
		_, err = certgo.SignServerCertificate(yamlPath)
	case "client":
		_, err = certgo.SignClientCertificate(yamlPath)
	}
	if err != nil {
		logger.Error("CMD", "failed to create cert")
		return
	}
	logger.Info("CMD", "create cert success")
}
