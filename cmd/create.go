package cmd

import "github.com/spf13/cobra"

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "used to create private key, certificate signing request, and certificate",
	Long:  "used to create private key, certificate signing request, and certificate",
}

func init() {
	rootCmd.AddCommand(createCmd)
}
