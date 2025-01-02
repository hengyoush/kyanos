package cmd

import (
	"kyanos/agent/protocol/rocketmq"

	"github.com/spf13/cobra"
)

var rocketmqCmd *cobra.Command = &cobra.Command{
	Use:   "rocketmq",
	Short: "watch RocketMQ message",
	Run: func(cmd *cobra.Command, args []string) {
		options.MessageFilter = rocketmq.Filter{}
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	rocketmqCmd.PersistentFlags().SortFlags = false
	copy := *rocketmqCmd
	watchCmd.AddCommand(&copy)
	copy2 := *rocketmqCmd
	statCmd.AddCommand(&copy2)
}
