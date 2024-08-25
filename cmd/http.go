package cmd

import (
	"kyanos/agent"
	"kyanos/agent/protocol/filter"

	"github.com/spf13/cobra"
)

var httpCmd *cobra.Command = &cobra.Command{
	Use:   "http --path /foo/bar",
	Short: "watch HTTP message",
	Run: func(cmd *cobra.Command, args []string) {
		path, err := cmd.Flags().GetString("path")
		if err != nil {
			logger.Fatalf("invalid path: %v\n", err)
		}
		startAgent(agent.AgentOptions{
			MessageFilter: filter.HttpFilter{
				TargetPath: path,
			},
		})
	},
}

func init() {
	httpCmd.Flags().String("path", "", "--path /foo/bar")
	httpCmd.Flags().SortFlags = false
	httpCmd.PersistentFlags().SortFlags = false
	watchCmd.AddCommand(httpCmd)
}
