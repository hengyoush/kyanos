package cmd

import (
	"kyanos/agent/protocol/mysql"

	"github.com/spf13/cobra"
)

var mysqlCmd *cobra.Command = &cobra.Command{
	Use:   "mysql",
	Short: "watch MYSQL message",
	Run: func(cmd *cobra.Command, args []string) {
		options.MessageFilter = mysql.MysqlFilter{}
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	mysqlCmd.PersistentFlags().SortFlags = false
	copy := *mysqlCmd
	watchCmd.AddCommand(&copy)
	copy2 := *mysqlCmd
	statCmd.AddCommand(&copy2)
}
