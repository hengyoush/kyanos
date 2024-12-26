package cmd

import (
	"kyanos/agent/protocol"
	"regexp"

	"github.com/spf13/cobra"
)

var httpCmd = &cobra.Command{
	Use:   "http [--method METHODS|--path PATH|--path-regex REGEX|--path-prefix PREFIX|--host HOSTNAME]",
	Short: "watch HTTP message",
	Long:  `Filter HTTP messages based on method, path (strict, regex, prefix), or host. Filter flags are combined with AND(&&).`,
	Run: func(cmd *cobra.Command, args []string) {
		methods, err := cmd.Flags().GetStringSlice("method")
		if err != nil {
			logger.Fatalf("invalid method: %v\n", err)
		}
		path, err := cmd.Flags().GetString("path")
		if err != nil {
			logger.Fatalf("invalid path: %v\n", err)
		}
		host, err := cmd.Flags().GetString("host")
		if err != nil {
			logger.Fatalf("invalid host: %v\n", err)
		}
		var (
			pathReg *regexp.Regexp
		)
		if pathRegStr, err := cmd.Flags().GetString("path-regex"); err != nil {
			logger.Fatalf("invalid path-regex: %v\n", err)
		} else if len(pathRegStr) > 0 {
			if pathReg, err = regexp.Compile(pathRegStr); err != nil {
				logger.Fatalf("invalid path-regex: %v\n", err)
			}
		}
		pathPrefix, err := cmd.Flags().GetString("path-prefix")
		if err != nil {
			logger.Fatalf("invalid path-prefix: %v\n", err)
		}

		options.MessageFilter = protocol.HttpFilter{
			TargetPath:       path,
			TargetPathReg:    pathReg,
			TargetPathPrefix: pathPrefix,
			TargetHostName:   host,
			TargetMethods:    methods,
		}
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	httpCmd.Flags().StringSlice("method", []string{}, "Specify the HTTP method to monitor(GET, POST), seperate by ','")
	httpCmd.Flags().String("host", "", "Specify the HTTP host to monitor, like: 'ubuntu.com'")
	httpCmd.Flags().String("path", "", "Specify the HTTP path to monitor, like: '/foo/bar'")
	httpCmd.Flags().String("path-regex", "", "Specify the regex for HTTP path to monitor, like: '\\/foo\\/bar\\/\\d+'")
	httpCmd.Flags().String("path-prefix", "", "Specify the prefix of HTTP path to monitor, like: '/foo'")

	httpCmd.Flags().SortFlags = false
	httpCmd.PersistentFlags().SortFlags = false
	copy := *httpCmd
	watchCmd.AddCommand(&copy)
	copy2 := *httpCmd
	statCmd.AddCommand(&copy2)
}
