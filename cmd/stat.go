package cmd

import (
	"fmt"
	"kyanos/agent"
	"kyanos/agent/analysis"
	"slices"

	"github.com/spf13/cobra"
)

var statCmd = &cobra.Command{
	Use:              "stat [-t -q -p -n -s] [--sample 10] [-g remote-ip|remote-port|local-port|protocol]",
	Short:            "Analysis connections statistics",
	PersistentPreRun: func(cmd *cobra.Command, args []string) { Mode = AnalysisMode },
	Run: func(cmd *cobra.Command, args []string) {
		startAgent(agent.AgentOptions{LatencyFilter: initLatencyFilter(cmd), SizeFilter: initSizeFilter(cmd)})
	},
}
var enabledMetricsString string
var displayLimit int
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

func createAnalysisOptions() (analysis.AnalysisOptions, error) {
	options := analysis.AnalysisOptions{
		EnabledMetricTypeSet: make(analysis.MetricTypeSet),
	}
	err := validateEnabledMetricsString()
	if err != nil {
		logger.Errorln(err)
		return analysis.AnalysisOptions{}, err
	}
	enabledMetricsBytes := []byte(enabledMetricsString)
	if slices.Contains(enabledMetricsBytes, 't') {
		options.EnabledMetricTypeSet[analysis.TotalDuration] = true
	}
	if slices.Contains(enabledMetricsBytes, 'q') {
		options.EnabledMetricTypeSet[analysis.RequestSize] = true
	}
	if slices.Contains(enabledMetricsBytes, 'p') {
		options.EnabledMetricTypeSet[analysis.ResponseSize] = true
	}
	if slices.Contains(enabledMetricsBytes, 'n') {
		options.EnabledMetricTypeSet[analysis.BlackBoxDuration] = true
	}
	if slices.Contains(enabledMetricsBytes, 's') {
		options.EnabledMetricTypeSet[analysis.ReadFromSocketBufferDuration] = true
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
	return options, nil
}

func init() {
	statCmd.PersistentFlags().StringVarP(&enabledMetricsString, "metrics", "m", "t", "-m pqtsn")
	statCmd.PersistentFlags().IntVarP(&sampleCount, "sample", "s", 0, "-s 10")
	statCmd.PersistentFlags().IntVarP(&displayLimit, "limit", "l", 10, "-l 20")
	statCmd.PersistentFlags().StringVarP(&groupBy, "group-by", "g", "remote-ip", "-g remote-ip")
	statCmd.PersistentFlags().Float64("latency", 0, "--latency 100 # millseconds")
	statCmd.PersistentFlags().Int64("req-size", 0, "--req-size 1024 # bytes")
	statCmd.PersistentFlags().Int64("resp-size", 0, "--resp-size 1024 # bytes")

	statCmd.Flags().SortFlags = false
	statCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(statCmd)
}
