package cmd

import (
	"strings"

	certgo "github.com/Alonza0314/cert-go"
	logger "github.com/Alonza0314/logger-go"
	"github.com/spf13/cobra"
)

var privateKeyCmd = &cobra.Command{
	Use:   "private-key",
	Short: "used to create private key",
	Long:  "used to create private key, you need to specify the key path you want to save",
	Run:   createPrivateKey,
}

func init() {
	privateKeyCmd.Flags().StringP("out", "o", "", "specify the output path of the private key")
	privateKeyCmd.Flags().BoolP("force", "f", false, "overwrite the private key if it already exists")

	if err := privateKeyCmd.MarkFlagRequired("out"); err != nil {
		logger.Error("cert-go", err.Error())
	}

	createCmd.AddCommand(privateKeyCmd)
}

func createPrivateKey(cmd *cobra.Command, args []string) {
	outputPath, err := cmd.Flags().GetString("out")
	if err != nil {
		logger.Error("cert-go", err.Error())
		return
	}
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		logger.Error("cert-go", err.Error())
		return
	}

	logger.Info("cert-go", "start to create private key")
	if _, err := certgo.CreatePrivateKey(outputPath, force); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			logger.Error("cert-go", "failed to create private key")
			return
		}
		logger.Error("cert-go", "failed to create private key")
		return
	}
	logger.Info("cert-go", "create private key success")
}
