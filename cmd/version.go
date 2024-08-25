package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version number of kyanos",
	Long:  `Print version number of kyanos`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("kyanos version v1.0.0 -- Release")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
