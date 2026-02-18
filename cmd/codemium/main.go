package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "codemium",
		Short: "Generate code statistics across repositories",
	}

	root.AddCommand(newAuthCmd())
	root.AddCommand(newAnalyzeCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "login",
		Short: "Authenticate with a provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not implemented")
		},
	})
	return cmd
}

func newAnalyzeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "analyze",
		Short: "Analyze repositories and generate code statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not implemented")
		},
	}
}
