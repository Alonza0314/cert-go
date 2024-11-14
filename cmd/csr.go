package cmd

import (
	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/logger"
	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
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
	csrCmd.MarkFlagRequired("yaml")
	csrCmd.MarkFlagRequired("type")

	createCmd.AddCommand(csrCmd)
}

func createCsr(cmd *cobra.Command, args []string) {
	yamlPath, err := cmd.Flags().GetString("yaml")
	if err != nil {
		logger.Error("CMD", err.Error())
		return
	}
	csrType, err := cmd.Flags().GetString("type")
	if err != nil {
		logger.Error("CMD", err.Error())
		return
	}

	if csrType != "intermediate" && csrType != "server" && csrType != "client" {
		logger.Error("CMD", "invalid csr type, please specify the type of the certificate: [intermediate, server, client]")
		return
	}

	logger.Info("CMD", "start to create csr")
	var cfg model.CAConfig
	if err := util.ReadYamlFileToStruct(yamlPath, &cfg); err != nil {
		logger.Error("CMD", "failed to create csr")
		return
	}
	switch csrType {
	case "intermediate":
		_, err = certgo.CreateCsr(cfg.CA.Intermediate)
	case "server":
		_, err = certgo.CreateCsr(cfg.CA.Server)
	case "client":
		_, err = certgo.CreateCsr(cfg.CA.Client)
	}
	if err != nil {
		logger.Error("CMD", "failed to create csr")
		return
	}
	logger.Info("CMD", "create csr success")
}
