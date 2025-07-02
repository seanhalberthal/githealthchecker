package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version can be set at build time using ldflags
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "githealthchecker",
	Short: "A comprehensive CLI tool for analyzing Git repository health",
	Long: `Git Health Checker is a comprehensive CLI tool that analyzes Git repositories 
for common issues, security vulnerabilities, and maintenance problems.

It provides detailed health reports covering security, performance, 
code quality, and maintenance aspects.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check for --version flag
		version, _ := cmd.Flags().GetBool("version")
		if version {
			fmt.Printf("githealthchecker version %s\n", Version)
			return
		}
		fmt.Println("Git Health Checker - Use 'githealthchecker help' for available commands")
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default is .healthcheck.yaml)")
	rootCmd.PersistentFlags().StringP("format", "f", "table", "output format (table, json, markdown)")
	rootCmd.PersistentFlags().StringP("output", "o", "", "output file path")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolP("version", "", false, "show version information")

	// Add version command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("githealthchecker version %s\n", Version)
		},
	})
}
