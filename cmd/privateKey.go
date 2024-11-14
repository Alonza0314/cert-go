package cmd

import (
	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/logger"
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
	privateKeyCmd.MarkFlagRequired("output")

	createCmd.AddCommand(privateKeyCmd)
}

func createPrivateKey(cmd *cobra.Command, args []string) {
	outputPath, err := cmd.Flags().GetString("out")
	if err != nil {
		logger.Error("CMD", err.Error())
		return
	}

	logger.Info("CMD", "start to create private key")
	if _, err := certgo.CreatePrivateKey(outputPath); err != nil {
		logger.Error("CMD", "failed to create private key")
		return
	}
	logger.Info("CMD", "create private key success")
}
