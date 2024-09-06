package cmd

import (
	"kyanos/agent"
	"kyanos/agent/analysis"

	"github.com/spf13/cobra"
)

var analysisCmd = &cobra.Command{
	Use:              "analysis [-t -q -p -n -s] [--sample 10] [-g remote-ip|remote-port|local-port|protocol]",
	Short:            "Analysis connections statistics",
	PersistentPreRun: func(cmd *cobra.Command, args []string) { Mode = AnalysisMode },
	Run: func(cmd *cobra.Command, args []string) {
		startAgent(agent.AgentOptions{LatencyFilter: initLatencyFilter(cmd), SizeFilter: initSizeFilter(cmd)})
	},
}

var enableTotalDuration bool
var enableRequestSize bool
var enableRespSize bool
var enableNetworkDuration bool
var enableReadFromSocketDuration bool
var sampleCount int
var groupBy string

func createAnalysisOptions() analysis.AnalysisOptions {
	options := analysis.AnalysisOptions{
		EnabledMetricTypeSet: make(analysis.MetricTypeSet),
	}
	if enableTotalDuration {
		options.EnabledMetricTypeSet[analysis.TotalDuration] = true
	}
	if enableRequestSize {
		options.EnabledMetricTypeSet[analysis.RequestSize] = true
	}
	if enableRespSize {
		options.EnabledMetricTypeSet[analysis.ResponseSize] = true
	}
	if enableNetworkDuration {
		options.EnabledMetricTypeSet[analysis.BlackBoxDuration] = true
	}
	if enableReadFromSocketDuration {
		options.EnabledMetricTypeSet[analysis.ReadFromSocketBufferDuration] = true
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
	return options
}

func init() {
	analysisCmd.PersistentFlags().BoolVarP(&enableTotalDuration, "total", "t", true, "-t")
	analysisCmd.PersistentFlags().BoolVarP(&enableRequestSize, "request-size", "q", false, "-q")
	analysisCmd.PersistentFlags().BoolVarP(&enableRespSize, "response-size", "r", false, "-q")
	analysisCmd.PersistentFlags().BoolVarP(&enableNetworkDuration, "network", "n", false, "-n")
	analysisCmd.PersistentFlags().BoolVarP(&enableReadFromSocketDuration, "socket", "s", false, "-s")
	analysisCmd.PersistentFlags().IntVar(&sampleCount, "sample", 0, "--sample 10")
	analysisCmd.PersistentFlags().StringVarP(&groupBy, "group-by", "g", "remote-ip", "-g remote-ip")
	analysisCmd.PersistentFlags().Float64("latency", 0, "--latency 100 # millseconds")
	analysisCmd.PersistentFlags().Int64("req-size", 0, "--req-size 1024 # bytes")
	analysisCmd.PersistentFlags().Int64("resp-size", 0, "--resp-size 1024 # bytes")

	analysisCmd.Flags().SortFlags = false
	analysisCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(analysisCmd)
}
