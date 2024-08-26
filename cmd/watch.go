package cmd

import (
	"fmt"
	"kyanos/agent"

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
				startAgent(agent.AgentOptions{})
			}
		}
	},
}

func init() {
	watchCmd.Flags().BoolP("list", "l", false, "--list # list all support protocols")
	watchCmd.PersistentFlags().Float64("latency", 0, "--latency 100 # millseconds")
	watchCmd.Flags().SortFlags = false
	watchCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(watchCmd)
}
