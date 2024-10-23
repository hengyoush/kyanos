package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var watchCmd = &cobra.Command{
	Use: "watch [http|redis|mysql [flags]]",
	Example: `
sudo kyanos watch
sudo kyanos watch http --side server --pid 1234 --path /foo/bar --host ubuntu.com
sudo kyanos watch redis --comands GET,SET --keys foo,bar --key-prefix app1:
sudo kyanos watch mysql --latency 100 --req-size 1024 --resp-size 2048
	`,
	Short:            "Watch the request/response pair and print body to the console",
	PersistentPreRun: func(cmd *cobra.Command, args []string) { Mode = WatchMode },
	Run: func(cmd *cobra.Command, args []string) {
		list, err := cmd.Flags().GetBool("list")
		if err != nil {
			logger.Errorln(err)
		} else {
			if list {
				fmt.Println([]string{"http", "redis", "mysql"})
			} else {
				options.LatencyFilter = initLatencyFilter(cmd)
				options.SizeFilter = initSizeFilter(cmd)
				startAgent()
			}
		}
	},
}

func init() {
	watchCmd.Flags().BoolP("list", "l", false, "list all support protocols")
	watchCmd.PersistentFlags().Float64("latency", 0, "Filter based on request response time")
	watchCmd.PersistentFlags().Int64("req-size", 0, "Filter based on request bytes size")
	watchCmd.PersistentFlags().Int64("resp-size", 0, "Filter based on response bytes size")
	watchCmd.PersistentFlags().BoolVar(&options.WatchOptions.DebugOutput, "debug-output", false, "Print output to console instead display ui")
	watchCmd.PersistentFlags().StringVarP(&options.WatchOptions.Opts, "output", "o", "", "Can be `wide`")
	watchCmd.PersistentFlags().IntVar(&options.WatchOptions.MaxRecordContentDisplayBytes, "max-print-bytes", 1024, "Control how may bytes of record's req/resp can be printed, \n exceeded part are truncated")
	watchCmd.PersistentFlags().StringVar(&SidePar, "side", "all", "Filter based on connection side. can be: server | client")
	watchCmd.Flags().SortFlags = false
	watchCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(watchCmd)
}
