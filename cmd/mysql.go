package cmd

import (
	"kyanos/agent"
	"kyanos/agent/protocol/mysql"

	"github.com/spf13/cobra"
)

var mysqlCmd *cobra.Command = &cobra.Command{
	Use:   "mysql ",
	Short: "watch MYSQL message",
	Run: func(cmd *cobra.Command, args []string) {
		startAgent(agent.AgentOptions{
			MessageFilter: mysql.MysqlFilter{},
			LatencyFilter: initLatencyFilter(cmd),
			SizeFilter:    initSizeFilter(cmd),
		})
	},
}

func init() {
	mysqlCmd.PersistentFlags().SortFlags = false
	watchCmd.AddCommand(mysqlCmd)
}
