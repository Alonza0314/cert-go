package cmd

import (
	"io"
	"os"

	"github.com/Alonza0314/cert-go/model"
	"github.com/Alonza0314/cert-go/util"
	logger "github.com/Alonza0314/logger-go"
	"github.com/spf13/cobra"
)

var bundleChainCmd = &cobra.Command{
	Use:   "bundle-chain",
	Short: "bundle root and intermediate certificates into one PEM file",
	Long:  "Reads your CA config YAML and concatenates the intermediate then root cert into a single PEM bundle",
	Run:   bundleChain,
}

func init() {
	createCmd.AddCommand(bundleChainCmd)

	bundleChainCmd.Flags().StringP("yaml", "y", "", "path to CA configuration YAML")
	bundleChainCmd.Flags().StringP("out", "o", "", "output path for the PEM bundle")
	bundleChainCmd.Flags().BoolP("force", "f", false, "overwrite existing bundle if present")

	_ = bundleChainCmd.MarkFlagRequired("yaml")
	_ = bundleChainCmd.MarkFlagRequired("out")
}

func bundleChain(cmd *cobra.Command, args []string) {
	yamlPath, _ := cmd.Flags().GetString("yaml")
	outPath, _ := cmd.Flags().GetString("out")
	force, _ := cmd.Flags().GetBool("force")

	// refuse if exists and no force
	if util.FileExists(outPath) && !force {
		logger.Error("cert-go", "bundle file already exists; use --force to overwrite")
		return
	}

	// remove if forcing
	if util.FileExists(outPath) {
		_ = util.FileDelete(outPath)
	}

	// load config
	var cfg model.CAConfig
	if err := util.ReadYamlFileToStruct(yamlPath, &cfg); err != nil {
		logger.Error("cert-go", "failed to read YAML: "+err.Error())
		return
	}

	// order: intermediate first, then root
	chainFiles := []string{
		cfg.CA.Intermediate.CertFilePath,
		cfg.CA.Root.CertFilePath,
	}

	// open output
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error("cert-go", "cannot create bundle file: "+err.Error())
		return
	}
	defer f.Close()

	// append each cert
	for _, path := range chainFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			logger.Error("cert-go", "cannot read cert "+path+": "+err.Error())
			return
		}
		if _, err := io.WriteString(f, string(data)); err != nil {
			logger.Error("cert-go", "failed to write to bundle: "+err.Error())
			return
		}
	}

	logger.Info("cert-go", "bundle-chain succeeded, output at "+outPath)
}
