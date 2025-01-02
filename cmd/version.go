package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version -X "kyanos/cmd.Version={{.Version}}"
	Version string
	// BuildTime -X "kyanos/cmd.CommitID={{.Commit}}"
	BuildTime string
	// CommitID -X "kyanos/cmd.BuildTime={{.Date}}"
	CommitID   string
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version of kyanos",
		Run: func(cmd *cobra.Command, args []string) {
			// The following vars are set by the linker during build. See the .goreleaser.yaml
			// reference: https://goreleaser.com/customization/builds/
			cmd.Println(fmt.Sprintf("Version: %v", Version))
			cmd.Println(fmt.Sprintf("BuildTime: %v", BuildTime))
			cmd.Println(fmt.Sprintf("CommitID: %v", CommitID))
		},
	}
)

func init() {
	rootCmd.AddCommand(versionCmd)
}
