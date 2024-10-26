package cmd

import (
	"fmt"
	anc "kyanos/agent/analysis/common"
	"kyanos/bpf"
	"slices"
	"strings"

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
var subGroupBy string
var slowMode bool
var bigRespModel bool
var bigReqModel bool
var timeLimit int
var duration int
var SUPPORTED_METRICS_SHORT = []byte{'t', 'q', 'p', 'n', 's'}
var SUPPORTED_METRICS = []string{"total-time", "reqsize", "respsize", "network-time", "internal-time", "socket-time"}

func validateEnabledMetricsString() error {
	for _, m := range []byte(enabledMetricsString) {
		if !slices.Contains(SUPPORTED_METRICS_SHORT, m) {
			return fmt.Errorf("invalid parameter: '-m %s', only support: %s", enabledMetricsString, SUPPORTED_METRICS_SHORT)
		}
	}
	return nil
}

func createAnalysisOptions() (anc.AnalysisOptions, error) {
	options := anc.AnalysisOptions{
		EnabledMetricTypeSet: make(anc.MetricTypeSet),
	}
	switch strings.ToLower(enabledMetricsString) {
	case "t", "total-time":
		options.EnabledMetricTypeSet[anc.TotalDuration] = true
	case "q", "reqsize":
		options.EnabledMetricTypeSet[anc.RequestSize] = true
	case "p", "respsize":
		options.EnabledMetricTypeSet[anc.ResponseSize] = true
	case "n", "network-time", "internal-time":
		options.EnabledMetricTypeSet[anc.BlackBoxDuration] = true
	case "s", "socket-time":
		options.EnabledMetricTypeSet[anc.ReadFromSocketBufferDuration] = true
	default:
		logger.Fatalf("invalid parameter: '-m %s', only support: `%s` and %s", enabledMetricsString, SUPPORTED_METRICS_SHORT, SUPPORTED_METRICS)
	}

	if sampleCount < 0 {
		sampleCount = 0
	}
	options.SampleLimit = sampleCount
	if strings.Contains(groupBy, "/") {
		split := strings.Split(groupBy, "/")
		groupBy = split[0]
		subGroupBy = split[1]
	} else {
		subGroupBy = "none"
	}
	for key, value := range anc.ClassfierTypeNames {
		if value == groupBy {
			options.ClassfierType = key
		}
		if value == subGroupBy && subGroupBy != "" {
			options.SubClassfierType = key
		}
	}
	options.SlowMode = slowMode
	options.BigReqMode = bigReqModel
	options.BigRespMode = bigRespModel
	options.ProtocolSpecificClassfiers = make(map[bpf.AgentTrafficProtocolT]anc.ClassfierType)
	// currently only set it hardly
	options.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolTKProtocolHTTP] = anc.HttpPath
	options.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolTKProtocolRedis] = anc.RedisCommand
	options.ProtocolSpecificClassfiers[bpf.AgentTrafficProtocolTKProtocolMySQL] = anc.RemoteIp
	options.TimeLimit = timeLimit

	options.Overview = overview
	return options, nil
}
func init() {
	statCmd.PersistentFlags().StringVarP(&enabledMetricsString, "metric", "m", "t", `Specify the statistical dimensions, including:
	t/total-time:  total time taken for request response,
	q/reqsize:  request size,
	p/respsize:  response size,
	n/network-time:  network device latency,
	s/socket-time:  time spent reading from the socket buffer`)
	statCmd.PersistentFlags().IntVarP(&sampleCount, "samples-limit", "s", 0,
		"Specify the number of samples to be attached for each result.\n"+
			"By default, only a summary  is output.\n"+
			"refer to the '--full-body' option.")
	statCmd.PersistentFlags().StringVarP(&groupBy, "group-by", "g", "default",
		"Specify aggregation dimension: \n"+
			"('conn', 'local-port', 'remote-port', 'remote-ip', 'protocol', 'http-path', 'none')\n"+
			"note: 'none' is aggregate all req-resp pair together")
	// statCmd.PersistentFlags().StringVar(&subGroupBy, "sub-group-by", "default",
	// 	"Specify sub aggregation dimension: like `group-by`, but before set this option you must specify `group-by`")

	// inspect options
	statCmd.PersistentFlags().BoolVar(&slowMode, "slow", false, "Find slowest records")
	statCmd.PersistentFlags().BoolVar(&bigReqModel, "bigreq", false, "Find biggest request size records")
	statCmd.PersistentFlags().BoolVar(&bigRespModel, "bigresp", false, "Find biggest response size records")
	statCmd.PersistentFlags().IntVar(&timeLimit, "time", 10, "")
	// statCmd.PersistentFlags().IntVarP(&duration, "duration", "d", 10, "")

	// common
	statCmd.PersistentFlags().Float64("latency", 0, "Filter based on request response time")
	statCmd.PersistentFlags().Int64("req-size", 0, "Filter based on request bytes size")
	statCmd.PersistentFlags().Int64("resp-size", 0, "Filter based on response bytes size")
	statCmd.PersistentFlags().StringVar(&SidePar, "side", "all", "Filter based on connection side. can be: server | client")

	statCmd.Flags().SortFlags = false
	statCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(statCmd)
}
