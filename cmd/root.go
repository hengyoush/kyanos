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
	Use:   "kyanos <command> [<args>]",
	Short: "Kyanos is a user-friendly, fast, non-intrusive command-line tool base on eBPF to find/analyze/diagnose network issues.",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	Run: func(cmd *cobra.Command, args []string) {
		startAgent(agent.AgentOptions{})
	},
}

// var LogDir string
// var Verbose bool
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

func init() {
	// rootCmd.PersistentFlags().StringVar(&LogDir, "log-dir", "", "log file dir")
	// rootCmd.PersistentFlags().BoolVar(&Daemon, "daemon", false, "run in background")
	rootCmd.PersistentFlags().Int64VarP(&FilterPid, "pid", "p", 0, "specify pid to trace, default trace all process")
	rootCmd.PersistentFlags().StringSliceVarP(&RemotePorts, common.RemotePortsVarName, "", []string{}, "specify remote ports to trace, default trace all")
	rootCmd.PersistentFlags().StringSliceVarP(&LocalPorts, common.LocalPortsVarName, "", []string{}, "specify local ports to trace, default trace all")
	rootCmd.PersistentFlags().StringSliceVarP(&RemoteIps, common.RemoteIpsVarName, "", []string{}, "specify remote ips to trace, default trace all")
	// rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "print verbose message")
	rootCmd.PersistentFlags().StringVar(&IfName, "ifname", "eth0", "--ifname eth0")
	rootCmd.PersistentFlags().MarkHidden("compatible")
	rootCmd.PersistentFlags().StringVar(&BTFFilePath, "btf", "", "btf file path")
	rootCmd.PersistentFlags().IntVar(&BPFVerifyLogSize, "bpf-verify-log-size", 1*1024*1024, "--bpf-verify-log-size 1024")
	rootCmd.PersistentFlags().IntVar(&KernEvtPerfEventBufferSize, "kern-perf-event-buffer-size", 1*1024*1024, "--kern-perf-event-buffer-size 1024")
	rootCmd.PersistentFlags().IntVar(&KernEvtPerfEventBufferSize, "data-perf-event-buffer-size", 30*1024*1024, "--data-perf-event-buffer-size 1024")

	// log config
	rootCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "print more logs helpful to debug")
	rootCmd.PersistentFlags().Int32Var(&DefaultLogLevel, "default-log-level", 3, "--default-log-level 4 # specify default log level, from 1(fatal level) to 5(debug level)")
	rootCmd.PersistentFlags().Int32Var(&AgentLogLevel, "agent-log-level", 0, "--agent-log-level 4 # specify agent module log level individually")
	rootCmd.PersistentFlags().Int32Var(&BPFEventLogLevel, "bpf-event-log-level", 0, "--bpf-event-log-level 4 # specify bpf event log level individually")
	rootCmd.PersistentFlags().Int32Var(&ConntrackLogLevel, "conntrack-log-level", 0, "--conntrack-log-level 4 # specify conntrack module log level individually")
	rootCmd.PersistentFlags().Int32Var(&ProtocolLogLevel, "protocol-log-level", 0, "--protocol-log-level 4 # specify protocol module log level individually")
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
