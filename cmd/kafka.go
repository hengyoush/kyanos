package cmd

import (
	"kyanos/agent/protocol/kafka"

	"github.com/spf13/cobra"
)

var _ = kafka.ProcessFetchReq
var kafkaCmd *cobra.Command = &cobra.Command{
	Use:   "kafka",
	Short: "watch Kafka message",
	Run: func(cmd *cobra.Command, args []string) {
		apikeys, err := cmd.Flags().GetInt32Slice("apikeys")
		if err != nil {
			logger.Fatalf("Invalid apikeys: %v\n", err)
		}
		topic, err := cmd.Flags().GetString("topic")
		if err != nil {
			logger.Fatalf("Invalid topic: %v\n", err)
		}
		producer, err := cmd.Flags().GetBool("producer")
		if err != nil {
			logger.Fatalf("Invalid producer: %v\n", err)
		}
		consumer, err := cmd.Flags().GetBool("consumer")
		if err != nil {
			logger.Fatalf("Invalid consumer: %v\n", err)
		}
		filter := kafka.NewKafkaFilter(apikeys, topic, producer, consumer)
		options.MessageFilter = filter
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	kafkaCmd.Flags().Int32Slice("apikeys", []int32{}, "Specify the apikeys to monitor (e.g., 0, 1), separated by ','")
	kafkaCmd.Flags().String("topic", "", "Specify the topic to monitor")
	kafkaCmd.Flags().Bool("producer", true, "Monitor only producer request")
	kafkaCmd.Flags().Bool("consumer", true, "Monitor only fetch request")

	kafkaCmd.PersistentFlags().SortFlags = false
	copy := *kafkaCmd
	watchCmd.AddCommand(&copy)
	copy2 := *kafkaCmd
	statCmd.AddCommand(&copy2)
}
