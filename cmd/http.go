package cmd

import (
	"kyanos/agent"
	"kyanos/agent/protocol/filter"

	"github.com/spf13/cobra"
)

var httpCmd *cobra.Command = &cobra.Command{
	Use:   "http --path /foo/bar --method GET,POST",
	Short: "watch HTTP message",
	Run: func(cmd *cobra.Command, args []string) {
		path, err := cmd.Flags().GetString("path")
		if err != nil {
			logger.Fatalf("invalid path: %v\n", err)
		}
		methods, err := cmd.Flags().GetStringSlice("method")
		if err != nil {
			logger.Fatalf("invalid method: %v\n", err)
		}
		startAgent(agent.AgentOptions{
			MessageFilter: filter.HttpFilter{
				TargetPath:    path,
				TargetMethods: methods,
			},
		})
	},
}

func init() {
	httpCmd.Flags().String("path", "", "--path /foo/bar")
	httpCmd.Flags().StringSlice("method", []string{"GET"}, "--method GET,POST")
	httpCmd.Flags().SortFlags = false
	httpCmd.PersistentFlags().SortFlags = false
	watchCmd.AddCommand(httpCmd)
}
