package main

import (
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage MCP authentication",
	Long: `Manage client certificates for MCP endpoint authentication.

Commands:
  login    Authenticate and provision a client certificate
  status   Show current certificate status`,
}

func init() {
	rootCmd.AddCommand(authCmd)
}
