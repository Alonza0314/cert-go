package cmd

import (
	"strings"

	certgo "github.com/Alonza0314/cert-go"
	"github.com/Alonza0314/cert-go/constants"
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
	privateKeyCmd.Flags().StringP("key", "k", "", "specify the type of the private key, <ecdsa> or <rsa>")

	if err := privateKeyCmd.MarkFlagRequired("out"); err != nil {
		logger.Error("cert-go", err.Error())
	}

	if err := privateKeyCmd.MarkFlagRequired("key"); err != nil {
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

	logger.Info("cert-go", "start to create private key")
	if _, err := certgo.CreatePrivateKey(outputPath, privateKeyType, force); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			logger.Error("cert-go", "failed to create private key")
			return
		}
		logger.Error("cert-go", "failed to create private key")
		return
	}
	logger.Info("cert-go", "create private key success")
}
