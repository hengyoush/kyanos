package cmd

import (
	"fmt"
	"kyanos/agent"

	"github.com/spf13/cobra"
)

var watchCmd = &cobra.Command{
	Use:              "watch [http|redis|mysql] [filter]",
	Short:            "Watch the request/response pair and print to the console",
	Long:             `It is possible to filter network requests based on specific protocol and print the request/response data to the console. `,
	PersistentPreRun: func(cmd *cobra.Command, args []string) { Mode = WatchMode },
	Run: func(cmd *cobra.Command, args []string) {
		list, err := cmd.Flags().GetBool("list")
		if err != nil {
			logger.Errorln(err)
		} else {
			if list {
				fmt.Println([]string{"http", "redis", "mysql"})
			} else {
				startAgent(agent.AgentOptions{LatencyFilter: initLatencyFilter(cmd), SizeFilter: initSizeFilter(cmd)})
			}
		}
	},
}

func init() {
	watchCmd.Flags().BoolP("list", "l", false, "--list # list all support protocols")
	watchCmd.PersistentFlags().Float64("latency", 0, "--latency 100 # millseconds")
	watchCmd.PersistentFlags().Int64("req-size", 0, "--req-size 1024 # bytes")
	watchCmd.PersistentFlags().Int64("resp-size", 0, "--resp-size 1024 # bytes")
	watchCmd.PersistentFlags().StringVar(&SidePar, "side", "all", "--side client|all|server")
	watchCmd.Flags().SortFlags = false
	watchCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(watchCmd)
}
