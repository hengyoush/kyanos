package cmd

import (
	"kyanos/agent/protocol/nats"

	"github.com/spf13/cobra"
)

var natsCmd *cobra.Command = &cobra.Command{
	Use:   "nats",
	Short: "watch NATS message",
	Run: func(cmd *cobra.Command, args []string) {
		protocols, err := cmd.Flags().GetStringSlice("protocols")
		if err != nil {
			logger.Fatalf("invalid protocol: %v\n", err)
		}
		subjects, err := cmd.Flags().GetStringSlice("subjects")
		if err != nil {
			logger.Fatalf("invalid subject: %v\n", err)
		}

		options.MessageFilter = nats.NatsFilter{
			Protocols: protocols,
			Subjects:  subjects,
		}
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	natsCmd.Flags().StringSlice("protocols", []string{}, "Specify the NATS protocol to monitor(PUB, SUB, MSG), seperate by ','")
	natsCmd.Flags().StringSlice("subjects", []string{}, "Specify the NATS subject to monitor, seperate by ','")

	natsCmd.Flags().SortFlags = false
	natsCmd.PersistentFlags().SortFlags = false
	copy := *natsCmd
	watchCmd.AddCommand(&copy)
	copy2 := *natsCmd
	statCmd.AddCommand(&copy2)
}
