/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "test command has no actual function",
	Long:  `test command has no actual function, it's just for testing that the tool is working properly`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("test success")
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
}
