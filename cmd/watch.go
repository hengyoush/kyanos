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
	watchCmd.Flags().BoolP("list", "l", false, "false | true")
	rootCmd.AddCommand(watchCmd)
}
