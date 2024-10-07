package cmd

import (
	"fmt"
	"kyanos/agent/analysis"
	anc "kyanos/agent/analysis/common"
	ac "kyanos/agent/common"
	"slices"

	"github.com/spf13/cobra"
)

var statCmd = &cobra.Command{
	Use:   "stat [--metrics pqtsn] [--samples 10] [--group-by conn|remote-ip|remote-port|local-port|protocol] [--sort-by avg|max|p50|p90|p99]",
	Short: "Analysis connections statistics. Aggregate metrics such as latency and size for request-response pairs.",
	Example: `
# Basic Usage, only count HTTP connections, print results when press 'ctlc+c' 
sudo kyanos stat http

# Print results 5 seconds periodically
sudo kyanos stat http -i 5

# Find the most slowly remote http server with '/example' api
sudo kyanos stat http --metrics t --group-by remote-ip --side client --path /example

# Same as above but also prints 3 slowest samples with full body
sudo kyanos stat http --metrics t --samples 3 --full-body ...

# Specify two metrics total duration & request size
sudo kyanos stat http --metrics tq --group-by remote-ip

# Sort by p99 of total duration's  (default is 'avg')
sudo kyanos stat http --metrics t --sort-by p99

# Limit the number of output connection results to 1.
sudo kyanos stat http --metrics t --limit 1

# In addition to request-response time, also track request-response size.
sudo kyanos stat http --metrics tqp 
	`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) { Mode = AnalysisMode },
	Run: func(cmd *cobra.Command, args []string) {
		startAgent(ac.AgentOptions{LatencyFilter: initLatencyFilter(cmd), SizeFilter: initSizeFilter(cmd)})
	},
}
var enabledMetricsString string
var displayLimit int
var sampleCount int
var groupBy string
var interval int
var sortByPar string
var fullBody bool
var SUPPORTED_METRICS = []byte{'t', 'q', 'p', 'n', 's', 'i'}

func validateEnabledMetricsString() error {
	for _, m := range []byte(enabledMetricsString) {
		if !slices.Contains(SUPPORTED_METRICS, m) {
			return fmt.Errorf("invalid parameter: '-m %s', only support: %s", enabledMetricsString, SUPPORTED_METRICS)
		}
	}
	return nil
}

func createAnalysisOptions() (anc.AnalysisOptions, error) {
	options := anc.AnalysisOptions{
		EnabledMetricTypeSet: make(anc.MetricTypeSet),
	}
	err := validateEnabledMetricsString()
	if err != nil {
		logger.Errorln(err)
		return anc.AnalysisOptions{}, err
	}
	enabledMetricsBytes := []byte(enabledMetricsString)
	if slices.Contains(enabledMetricsBytes, 't') {
		options.EnabledMetricTypeSet[anc.TotalDuration] = true
	}
	if slices.Contains(enabledMetricsBytes, 'q') {
		options.EnabledMetricTypeSet[anc.RequestSize] = true
	}
	if slices.Contains(enabledMetricsBytes, 'p') {
		options.EnabledMetricTypeSet[anc.ResponseSize] = true
	}
	if slices.Contains(enabledMetricsBytes, 'n') || slices.Contains(enabledMetricsBytes, 'i') {
		options.EnabledMetricTypeSet[anc.BlackBoxDuration] = true
	}
	if slices.Contains(enabledMetricsBytes, 's') {
		options.EnabledMetricTypeSet[anc.ReadFromSocketBufferDuration] = true
	}
	if sampleCount < 0 {
		sampleCount = 0
	}
	options.SampleLimit = sampleCount
	options.DisplayLimit = displayLimit

	for key, value := range analysis.ClassfierTypeNames {
		if value == groupBy {
			options.ClassfierType = key
		}
	}

	options.Interval = interval

	switch sortByPar {
	case "avg":
		options.SortBy = anc.Avg
	case "max":
		options.SortBy = anc.Max
	case "p50":
		options.SortBy = anc.P50
	case "P90":
		options.SortBy = anc.P90
	case "P99":
		options.SortBy = anc.P99
	default:
		logger.Warnf("unknown --sort-by flag: %s, use default '%s'", sortByPar, "avg")
		options.SortBy = anc.Avg
	}

	if fullBody {
		options.FullRecordBody = true
	}
	return options, nil
}
func init() {
	statCmd.PersistentFlags().StringVarP(&enabledMetricsString, "metrics", "m", "t", `Specify the statistical dimensions, including:
	t:  total time taken for request response,
	q:  request size,
	p:  response size,
	n:  network device latency,
	i:  internal application latency,
	s:  time spent reading from the socket buffer
	You can specify these flags individually or 
	combine them together like: '-m pq'`)
	statCmd.PersistentFlags().IntVarP(&sampleCount, "samples", "s", 0,
		"Specify the number of samples to be attached for each result.\n"+
			"By default, only a summary  is output.\n"+
			"refer to the '--full-body' option.")
	statCmd.PersistentFlags().BoolVar(&fullBody, "full-body", false, "Used with '--samples' option, print content of req-resp when print samples.")
	statCmd.PersistentFlags().IntVarP(&displayLimit, "limit", "l", 10, "Specify the number of output results.")
	statCmd.PersistentFlags().IntVarP(&interval, "interval", "i", 0, "Print statistics periodically, or if not specified, statistics will be displayed when stopped with `ctrl+c`.")
	statCmd.PersistentFlags().StringVarP(&groupBy, "group-by", "g", "remote-ip",
		"Specify aggregation dimension: \n"+
			"('conn', 'local-port', 'remote-port', 'remote-ip', 'protocol', 'http-path', 'none')\n"+
			"note: 'none' is aggregate all req-resp pair together")
	statCmd.PersistentFlags().StringVar(&sortByPar, "sort-by", "avg", "Specify the sorting method for the output results: ('avg', 'max', 'p50', 'p90', 'p99'")

	// common
	statCmd.PersistentFlags().Float64("latency", 0, "Filter based on request response time")
	statCmd.PersistentFlags().Int64("req-size", 0, "Filter based on request bytes size")
	statCmd.PersistentFlags().Int64("resp-size", 0, "Filter based on response bytes size")
	statCmd.PersistentFlags().StringVar(&SidePar, "side", "all", "Filter based on connection side. can be: server | client")

	statCmd.Flags().SortFlags = false
	statCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(statCmd)
}
