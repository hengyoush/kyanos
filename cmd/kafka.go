package cmd

import (
	"kyanos/agent/protocol/kafka"

	"github.com/spf13/cobra"
)

var _ = kafka.ProcessFetchReq
var kafkaCmd *cobra.Command = &cobra.Command{
	Use:   "kafka",
	Short: "watch RocketMQ message",
	Run: func(cmd *cobra.Command, args []string) {

		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	// kafkaCmd.Flags().Int32Slice("request-codes", []int32{}, "Specify the request codes to monitor (e.g., 10, 11), separated by ','")
	// kafkaCmd.Flags().StringSlice("languages", []string{}, "Specify the languages to monitor (e.g., Java, Go, Rust, CPP), separated by ','")

	kafkaCmd.PersistentFlags().SortFlags = false
	copy := *kafkaCmd
	watchCmd.AddCommand(&copy)
	copy2 := *kafkaCmd
	statCmd.AddCommand(&copy2)
}
