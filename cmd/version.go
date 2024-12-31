package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version    string
	BuildTime  string
	CommitID   string
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version of kyanos",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(fmt.Sprintf("Version: %v", Version))
			cmd.Println(fmt.Sprintf("BuildTime: %v", BuildTime))
			cmd.Println(fmt.Sprintf("CommitID: %v", CommitID))
		},
	}
)

func init() {
	rootCmd.AddCommand(versionCmd)
}
