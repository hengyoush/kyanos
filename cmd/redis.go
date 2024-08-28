package cmd

import (
	"kyanos/agent"
	"kyanos/agent/protocol/filter"

	"github.com/spf13/cobra"
)

var redisCmd *cobra.Command = &cobra.Command{
	Use:   "redis [--command COMMANDS]",
	Short: "watch Redis message",
	Run: func(cmd *cobra.Command, args []string) {
		commands, err := cmd.Flags().GetStringSlice("command")
		if err != nil {
			logger.Fatalf("invalid method: %v\n", err)
		}
		startAgent(agent.AgentOptions{
			MessageFilter: filter.RedisFilter{
				TargetCommands: commands,
			},
			LatencyFilter: initLatencyFilter(cmd),
			SizeFilter:    initSizeFilter(cmd),
		})
	},
}

func init() {
	redisCmd.Flags().StringSlice("command", []string{}, "--command GET,SET")
	redisCmd.Flags().SortFlags = false
	redisCmd.PersistentFlags().SortFlags = false
	watchCmd.AddCommand(redisCmd)
}
