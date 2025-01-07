package cmd

import (
	"kyanos/agent/protocol/rocketmq"
	"strings"

	"github.com/spf13/cobra"
)

var rocketmqCmd *cobra.Command = &cobra.Command{
	Use:   "rocketmq",
	Short: "watch RocketMQ message",
	Run: func(cmd *cobra.Command, args []string) {
		requestCodes, err := cmd.Flags().GetInt32Slice("request-codes")
		if err != nil {
			logger.Fatalf("Invalid request codes: %v\n", err)
		}

		languageStrings, err := cmd.Flags().GetStringSlice("languages")
		if err != nil {
			logger.Fatalf("Invalid languages: %v\n", err)
		}

		var languageCodes []rocketmq.LanguageCode
		for _, lang := range languageStrings {
			code, err := rocketmq.ConvertToLanguageCode(strings.ToUpper(lang))
			if err != nil {
				logger.Warnf("Invalid language code: %v\n", err)
				continue
			}
			languageCodes = append(languageCodes, code)
		}

		options.MessageFilter = rocketmq.Filter{
			TargetRequestCodes:  requestCodes,
			TargetLanguageCodes: languageCodes,
		}

		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	rocketmqCmd.Flags().Int32Slice("request-codes", []int32{}, "Specify the request codes to monitor (e.g., 100, 200), separated by ','")
	rocketmqCmd.Flags().StringSlice("languages", []string{}, "Specify the languages to monitor (e.g., Java, Go, Rust, CPP), separated by ','")

	rocketmqCmd.PersistentFlags().SortFlags = false
	copy := *rocketmqCmd
	watchCmd.AddCommand(&copy)
	copy2 := *rocketmqCmd
	statCmd.AddCommand(&copy2)
}
