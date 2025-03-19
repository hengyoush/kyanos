package cmd

import (
	"kyanos/agent/protocol/mongodb"

	"github.com/spf13/cobra"
)

var mongodbCmd *cobra.Command = &cobra.Command{
	Use:   "mongodb",
	Short: "watch mongodb message",
	Run: func(cmd *cobra.Command, args []string) {
		options.MessageFilter = mongodb.NewMongoDBFilter()
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {

	mongodbCmd.PersistentFlags().SortFlags = false
	copy := *mongodbCmd
	watchCmd.AddCommand(&copy)
	copy2 := *mongodbCmd
	statCmd.AddCommand(&copy2)
}
