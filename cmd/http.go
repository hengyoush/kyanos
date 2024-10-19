package cmd

import (
	"kyanos/agent/protocol"

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
		options.MessageFilter = protocol.HttpFilter{
			TargetPath:     path,
			TargetMethods:  methods,
			TargetHostName: host,
		}
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	httpCmd.Flags().StringSlice("method", []string{}, "Specify the HTTP method to monitor(GET, POST), seperate by ','")
	httpCmd.Flags().String("host", "", "Specify the HTTP host to monitor, like: 'ubuntu.com'")
	httpCmd.Flags().String("path", "", "Specify the HTTP path to monitor, like: '/foo/bar'")
	httpCmd.Flags().SortFlags = false
	httpCmd.PersistentFlags().SortFlags = false
	copy := *httpCmd
	watchCmd.AddCommand(&copy)
	copy2 := *httpCmd
	statCmd.AddCommand(&copy2)
}
