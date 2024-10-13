package cmd

import (
	"fmt"
	"kyanos/agent/analysis"
	anc "kyanos/agent/analysis/common"
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
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}
var enabledMetricsString string
var sampleCount int
var groupBy string
var SUPPORTED_METRICS = []byte{'t', 'q', 'p', 'n', 's'}

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
	switch enabledMetricsString {
	case "t":
		options.EnabledMetricTypeSet[anc.TotalDuration] = true
	case "q":
		options.EnabledMetricTypeSet[anc.RequestSize] = true
	case "p":
		options.EnabledMetricTypeSet[anc.ResponseSize] = true
	case "n":
		options.EnabledMetricTypeSet[anc.BlackBoxDuration] = true
	case "s":
		options.EnabledMetricTypeSet[anc.ReadFromSocketBufferDuration] = true
	default:
		logger.Fatalf("invalid parameter: '-m %s', only support: %s", enabledMetricsString, SUPPORTED_METRICS)
	}

	if sampleCount < 0 {
		sampleCount = 0
	}
	options.SampleLimit = sampleCount

	for key, value := range analysis.ClassfierTypeNames {
		if value == groupBy {
			options.ClassfierType = key
		}
	}
	return options, nil
}
func init() {
	statCmd.PersistentFlags().StringVarP(&enabledMetricsString, "metrics", "m", "t", `Specify the statistical dimensions, including:
	t:  total time taken for request response,
	q:  request size,
	p:  response size,
	n:  network device latency,
	s:  time spent reading from the socket buffer`)
	statCmd.PersistentFlags().IntVarP(&sampleCount, "samples", "s", 0,
		"Specify the number of samples to be attached for each result.\n"+
			"By default, only a summary  is output.\n"+
			"refer to the '--full-body' option.")
	statCmd.PersistentFlags().StringVarP(&groupBy, "group-by", "g", "remote-ip",
		"Specify aggregation dimension: \n"+
			"('conn', 'local-port', 'remote-port', 'remote-ip', 'protocol', 'http-path', 'none')\n"+
			"note: 'none' is aggregate all req-resp pair together")

	// common
	statCmd.PersistentFlags().Float64("latency", 0, "Filter based on request response time")
	statCmd.PersistentFlags().Int64("req-size", 0, "Filter based on request bytes size")
	statCmd.PersistentFlags().Int64("resp-size", 0, "Filter based on response bytes size")
	statCmd.PersistentFlags().StringVar(&SidePar, "side", "all", "Filter based on connection side. can be: server | client")

	statCmd.Flags().SortFlags = false
	statCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(statCmd)
}
