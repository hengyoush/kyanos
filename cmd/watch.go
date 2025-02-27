package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var maxRecords int
var supportedProtocols = []string{"http", "redis", "mysql", "rocketmq", "kafka", "mongodb"}
var watchCmd = &cobra.Command{
	Use: "watch [http|redis|mysql|rocketmq|mongodb] [flags]",
	Example: `
sudo kyanos watch
sudo kyanos watch http --side server --pid 1234 --path /foo/bar --host ubuntu.com
sudo kyanos watch redis --command GET,SET --keys foo,bar --key-prefix app1:
sudo kyanos watch mysql --latency 100 --req-size 1024 --resp-size 2048
sudo kyanos watch rocketmq --request-codes 10,11 --languages JAVA,Go
	`,
	Short:            "Capture the request/response recrods",
	PersistentPreRun: func(cmd *cobra.Command, args []string) { Mode = WatchMode },
	Run: func(cmd *cobra.Command, args []string) {
		list, err := cmd.Flags().GetBool("list")
		if err != nil {
			logger.Errorln(err)
		} else {
			if list {
				fmt.Println(supportedProtocols)
			} else {
				if len(args) > 0 {
					logger.Fatalln("current only support:", supportedProtocols)
				}
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
	watchCmd.PersistentFlags().IntVar(&maxRecords, "max-records", 100, "Limit the max number of table records")
	watchCmd.PersistentFlags().BoolVar(&options.WatchOptions.DebugOutput, "debug-output", false, "Print output to console instead display ui")
	watchCmd.PersistentFlags().StringVar(&options.WatchOptions.JsonOutput, "json-output", "", "Output in JSON format. Use 'stdout' to print to terminal, or provide a file path to write to a file")
	watchCmd.PersistentFlags().StringVar(&SidePar, "side", "all", "Filter based on connection side. can be: server | client")
	watchCmd.PersistentFlags().StringVarP(&options.WatchOptions.Opts, "output", "o", "", "Can be `wide`")
	watchCmd.PersistentFlags().IntVar(&options.WatchOptions.MaxRecordContentDisplayBytes, "max-print-bytes", 1024, "Control how may bytes of record's req/resp can be printed, \n exceeded part are truncated")
	watchCmd.PersistentFlags().BoolVar(&options.WatchOptions.TraceDevEvent, "trace-dev-event", true, "Collect dev layer events to measure network interface time spent.")
	watchCmd.PersistentFlags().BoolVar(&options.WatchOptions.TraceSocketEvent, "trace-socket-event", false, "Collect socket layer events to measure the time spent on socket data copying.")
	watchCmd.PersistentFlags().BoolVar(&options.WatchOptions.TraceSslEvent, "trace-ssl-event", true, "Collect SSL events to trace SSL connection data.")
	watchCmd.Flags().SortFlags = false
	watchCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(watchCmd)
}
