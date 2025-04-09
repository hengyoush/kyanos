package cmd

import (
	"kyanos/agent/protocol/dns"

	"github.com/spf13/cobra"
)

var dnsCmd *cobra.Command = &cobra.Command{
	Use:   "dns",
	Short: "watch DNS message",
	Run: func(cmd *cobra.Command, args []string) {
		host, err := cmd.Flags().GetString("host")
		if err != nil {
			logger.Fatalf("Invalid host: %v\n", err)
		}
		filter := dns.NewDNSFilter(host)
		options.MessageFilter = filter
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	dnsCmd.Flags().String("host", "", "Specify the host to monitor")
	dnsCmd.PersistentFlags().SortFlags = false
	copy := *dnsCmd
	watchCmd.AddCommand(&copy)
	copy2 := *dnsCmd
	statCmd.AddCommand(&copy2)
}
