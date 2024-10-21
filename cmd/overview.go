package cmd

import "github.com/spf13/cobra"

var overviewCmd = &cobra.Command{
	Use:   "overview [--metrics <metric_name>]",
	Short: "Overview the dependencies like mysql/redis/.. in one cmd line.",
	Example: `
# Basic Usage
sudo kyanos overview
`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) { Mode = AnalysisMode },
	Run: func(cmd *cobra.Command, args []string) {
		overview = true
		groupBy = "remote-ip/protocol-adaptive"
		startAgent()
	},
}

var overview bool

func init() {
	overviewCmd.PersistentFlags().StringVarP(&enabledMetricsString, "metrics", "m", "t", `Specify the statistical dimensions, including:
	t:  total time taken for request response,
	q:  request size,
	p:  response size,
	n:  network device latency,
	s:  time spent reading from the socket buffer`)

	overviewCmd.Flags().SortFlags = false
	overviewCmd.PersistentFlags().SortFlags = false
	rootCmd.AddCommand(overviewCmd)
}
