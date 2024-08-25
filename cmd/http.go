package cmd

import (
	"kyanos/agent"
	"kyanos/agent/protocol/filter"

	"github.com/spf13/cobra"
)

var httpCmd *cobra.Command = &cobra.Command{
	Use:   "http [--method METHODS|--path PATH|--host HOSTNAME]",
	Short: "watch HTTP message",
	Run: func(cmd *cobra.Command, args []string) {
		methods, err := cmd.Flags().GetStringSlice("method")
		if err != nil {
			logger.Fatalf("invalid method: %v\n", err)
		}
		path, err := cmd.Flags().GetString("path")
		if err != nil {
			logger.Fatalf("invalid path: %v\n", err)
		}
		host, err := cmd.Flags().GetString("host")
		if err != nil {
			logger.Fatalf("invalid host: %v\n", err)
		}
		startAgent(agent.AgentOptions{
			MessageFilter: filter.HttpFilter{
				TargetPath:     path,
				TargetMethods:  methods,
				TargetHostName: host,
			},
		})
	},
}

func init() {
	httpCmd.Flags().StringSlice("method", []string{}, "--method GET,POST")
	httpCmd.Flags().String("host", "", "--host www.baidu.com")
	httpCmd.Flags().String("path", "", "--path /foo/bar")
	httpCmd.Flags().SortFlags = false
	httpCmd.PersistentFlags().SortFlags = false
	watchCmd.AddCommand(httpCmd)
}
