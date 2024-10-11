package cmd

import (
	"kyanos/agent/protocol"

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
		keys, err := cmd.Flags().GetStringSlice("keys")
		if err != nil {
			logger.Fatalf("invalid keys: %v\n", err)
		}
		prefix, err := cmd.Flags().GetString("key-prefix")
		if err != nil {
			logger.Fatalf("invalid prefix: %v\n", err)
		}

		options.MessageFilter = protocol.RedisFilter{
			TargetCommands: commands,
			TargetKeys:     keys,
			KeyPrefix:      prefix,
		}
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	redisCmd.Flags().StringSlice("command", []string{}, "Specify the redis command to monitor(GET, SET), seperate by ','")
	redisCmd.Flags().StringSlice("keys", []string{}, "Specify the redis keys to monitor, seperate by ','")
	redisCmd.Flags().String("key-prefix", "", "Specify the redis key prefix to monitor")
	redisCmd.Flags().SortFlags = false
	redisCmd.PersistentFlags().SortFlags = false
	copy := *redisCmd
	watchCmd.AddCommand(&copy)
	copy2 := *redisCmd
	statCmd.AddCommand(&copy2)
}
