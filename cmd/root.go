package cmd

import (
	"fmt"
	"kyanos/agent"
	"kyanos/common"

	"github.com/jefurry/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logger *logrus.Logger = common.DefaultLog

var rootCmd = &cobra.Command{
	Use: `kyanos <command> [flags]`,
	Short: "Kyanos is a command-line tool for monitoring, troubleshooting, and analyzing network issues using eBPF. \n" +
		"It helps you quickly diagnose network-related problems in applications," +
		" such as slow queries, high traffic, and other anomalies.\n" +
		"More info: https://github.com/hengyoush/kyanos",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	DisableFlagsInUseLine: true,
	Example: `
sudo kyanos
sudo kyanos watch http --pid 1234 --path /foo/bar
sudo kyanos watch redis --comands GET,SET
sudo kyanos watch mysql --latency 100

sudo kyanos stat http --metrics t --interval 5
sudo kyanos stat http --metrics t --group-by remote-ip
sudo kyanos stat http --metrics t --samples 3 --full-body
sudo kyanos stat http --metrics tq --sort-by avg --group-by remote-ip`,
	Run: func(cmd *cobra.Command, args []string) {
		startAgent(agent.AgentOptions{})
	},
}

var Daemon bool
var Debug bool
var FilterPid int64
var RemotePorts []string
var LocalPorts []string
var RemoteIps []string
var LocalIps []string
var IfName string
var BTFFilePath string
var BPFVerifyLogSize int
var KernEvtPerfEventBufferSize int
var DataEvtPerfEventBufferSize int
var DefaultLogLevel int32
var AgentLogLevel int32
var BPFEventLogLevel int32
var ConntrackLogLevel int32
var ProtocolLogLevel int32
var UprobeLogLevel int32

func init() {
	rootCmd.PersistentFlags().Int64VarP(&FilterPid, "pid", "p", 0, "Filter by pid")
	rootCmd.PersistentFlags().StringSliceVarP(&RemotePorts, common.RemotePortsVarName, "", []string{}, "Filter by remote ports, seperate by ','")
	rootCmd.PersistentFlags().StringSliceVarP(&LocalPorts, common.LocalPortsVarName, "", []string{}, "Filter by local ports, seperate by ','")
	rootCmd.PersistentFlags().StringSliceVarP(&RemoteIps, common.RemoteIpsVarName, "", []string{}, "Filter by remote ips, seperate by ','")
	// rootCmd.PersistentFlags().StringVar(&IfName, "ifname", "eth0", "--ifname eth0")
	rootCmd.PersistentFlags().StringVar(&BTFFilePath, "btf", "", "specify kernel BTF file")

	// log config
	rootCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "print more logs helpful to debug")
	rootCmd.PersistentFlags().Int32Var(&DefaultLogLevel, "default-log-level", 3, "specify default log level, from 1(fatal level) to 5(debug level)")
	rootCmd.PersistentFlags().Int32Var(&AgentLogLevel, "agent-log-level", 0, "specify agent module log level individually")
	rootCmd.PersistentFlags().Int32Var(&BPFEventLogLevel, "bpf-event-log-level", 0, "specify bpf event log level individually")
	rootCmd.PersistentFlags().Int32Var(&ConntrackLogLevel, "conntrack-log-level", 0, "specify conntrack module log level individually")
	rootCmd.PersistentFlags().Int32Var(&ProtocolLogLevel, "protocol-log-level", 0, "specify protocol module log level individually")
	rootCmd.PersistentFlags().Int32Var(&UprobeLogLevel, "uprobe-log-level", 0, "specify uprobe module log level individually")

	// internal
	rootCmd.PersistentFlags().IntVar(&BPFVerifyLogSize, "bpf-verify-log-size", 10*1024, "--bpf-verify-log-size 1024")
	rootCmd.PersistentFlags().IntVar(&KernEvtPerfEventBufferSize, "kern-perf-event-buffer-size", 1*1024*1024, "--kern-perf-event-buffer-size 1024")
	rootCmd.PersistentFlags().IntVar(&KernEvtPerfEventBufferSize, "data-perf-event-buffer-size", 30*1024*1024, "--data-perf-event-buffer-size 1024")

	rootCmd.PersistentFlags().MarkHidden("default-log-level")
	rootCmd.PersistentFlags().MarkHidden("agent-log-level")
	rootCmd.PersistentFlags().MarkHidden("bpf-event-log-level")
	rootCmd.PersistentFlags().MarkHidden("conntrack-log-level")
	rootCmd.PersistentFlags().MarkHidden("protocol-log-level")
	rootCmd.PersistentFlags().MarkHidden("bpf-verify-log-size")
	rootCmd.PersistentFlags().MarkHidden("kern-perf-event-buffer-size")
	rootCmd.PersistentFlags().MarkHidden("data-perf-event-buffer-size")

	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false
	viper.BindPFlags(rootCmd.Flags())
	viper.BindPFlags(rootCmd.PersistentFlags())
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
