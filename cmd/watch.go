package cmd

import (
	"fmt"
	"kyanos/agent"
	"kyanos/agent/protocol/filter"

	"github.com/spf13/cobra"
)

var watchCmd = &cobra.Command{
	Use:   "watch [http|redis] --path /foo/bar",
	Short: "Watch the request/response pair and print to the console",
	Long:  `It is possible to filter network requests based on specific protocol and print the request/response data to the console. `,
	Run: func(cmd *cobra.Command, args []string) {
		list, err := cmd.Flags().GetBool("list")
		if err != nil {
			logger.Errorln(err)
		} else {
			if list {
				fmt.Println([]string{"http", "redis"})
			} else {
				startAgent(agent.AgentOptions{LatencyFilter: initLatencyFilter(cmd)})
			}
		}
	},
}

func initLatencyFilter(cmd *cobra.Command) filter.LatencyFilter {
	latency, err := cmd.Flags().GetFloat64("latency")
	if err != nil {
		logger.Fatalf("invalid latency: %v\n", err)
	}
	latencyFilter := filter.LatencyFilter{
		MinLatency: latency,
	}
	return latencyFilter
}

func init() {
	watchCmd.Flags().BoolP("list", "l", false, "--list # list all support protocols")
	watchCmd.PersistentFlags().Float64("latency", 0, "--latency 100 # millseconds")
	watchCmd.Flags().SortFlags = false
	watchCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(watchCmd)
}
