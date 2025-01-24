package cmd

import (
	"fmt"
	"kyanos/agent/metadata/k8s"
	"kyanos/common"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logger *common.Klogger = common.DefaultLog

var rootCmd = &cobra.Command{
	Use: `kyanos <command> [flags]`,
	Short: "Kyanos is a command-line tool for monitoring, troubleshooting, and analyzing network issues using eBPF. \n" +
		"It helps you quickly diagnose network-related problems in realtime," +
		" such as slow queries, high traffic, and other anomalies.\n" +
		"More info: https://github.com/hengyoush/kyanos",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	DisableFlagsInUseLine: true,
	Example: `
sudo kyanos
sudo kyanos watch http --pids 1234 --path /foo/bar
sudo kyanos watch redis --comands GET,SET
sudo kyanos watch mysql --latency 100

sudo kyanos stat http --metrics total-time
sudo kyanos stat http --metrics total-time --group-by remote-ip`,
	Run: func(cmd *cobra.Command, args []string) {
		startAgent()
	},
}

var Daemon bool
var Debug bool
var FilterPids []string
var RemotePorts []string
var LocalPorts []string
var RemoteIps []string
var LocalIps []string
var IfName string
var BTFFilePath string
var KernEvtPerfEventBufferSize int
var DataEvtPerfEventBufferSize int
var DefaultLogLevel int32
var AgentLogLevel int32
var BPFEventLogLevel int32
var ConntrackLogLevel int32
var ProtocolLogLevel int32
var UprobeLogLevel int32
var DockerEndpoint string
var ContainerdEndpoint string
var CriRuntimeEndpoint string
var ContainerId string
var ContainerName string
var PodName string

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&FilterPids, "pids", "p", []string{}, "Filter by pids, seperate by ','")
	rootCmd.PersistentFlags().StringVar(&options.FilterComm, "comm", "", "Filter by process name")
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

	// container
	rootCmd.PersistentFlags().StringVar(&ContainerId, "container-id", "", "Filter by container id (only TCP and UDP packets are supported)")
	rootCmd.PersistentFlags().StringVar(&ContainerName, "container-name", "", "Filter by container name (only TCP and UDP packets are supported)")
	rootCmd.PersistentFlags().StringVar(&PodName, "pod-name", "", "Filter by pod name (format: NAME.NAMESPACE, only TCP and UDP packets are supported)")
	rootCmd.PersistentFlags().StringVar(&DockerEndpoint, "docker-address", "unix:///var/run/docker.sock",
		`Address of Docker Engine service`)
	rootCmd.PersistentFlags().StringVar(&ContainerdEndpoint, "containerd-address", "/run/containerd/containerd.sock",
		`Address of containerd service`)
	rootCmd.PersistentFlags().StringVar(&CriRuntimeEndpoint, "cri-runtime-address", "",
		"Address of CRI container runtime service "+
			fmt.Sprintf("(default: uses in order the first successful one of [%s])",
				strings.Join(getDefaultCriRuntimeEndpoint(), ", ")))

	// pageNum of eBPF map
	rootCmd.PersistentFlags().IntVar(&options.SyscallPerfEventMapPageNum, "syscall-perf-event-map-page-num", 2048, "pageNum of eBPF map size for syscall data events buffer")
	rootCmd.PersistentFlags().IntVar(&options.SslPerfEventMapPageNum, "ssl-perf-event-map-page-num", 512, "pageNum of eBPF map size for ssl data events buffer")
	rootCmd.PersistentFlags().IntVar(&options.ConnPerfEventMapPageNum, "conn-perf-event-map-page-num", 4, "pageNum of eBPF map size for conn data events buffer")
	rootCmd.PersistentFlags().IntVar(&options.KernPerfEventMapPageNum, "kern-perf-event-map-page-num", 32, "pageNum of eBPF map size for kern events buffer")
	rootCmd.PersistentFlags().IntVar(&options.FirstPacketEventMapPageNum, "first-packet-event-map-page-num", 32, "pageNum of eBPF map size for first packet events buffer")

	// internal
	rootCmd.PersistentFlags().BoolVar(&options.PerformanceMode, "performance-mode", true, "--performance false")
	rootCmd.PersistentFlags().IntVar(&KernEvtPerfEventBufferSize, "kern-perf-event-buffer-size", 1*1024*1024, "--kern-perf-event-buffer-size 1024")
	rootCmd.PersistentFlags().IntVar(&KernEvtPerfEventBufferSize, "data-perf-event-buffer-size", 30*1024*1024, "--data-perf-event-buffer-size 1024")
	rootCmd.PersistentFlags().IntVar(&options.ConntrackCloseWaitTimeMills, "conntrack-close-wait-time-mills", 100, "--conntrack-close-wait-time-mills 100")

	rootCmd.PersistentFlags().BoolVar(&options.StartGopsServer, "gops", false, "start gops server")

	rootCmd.PersistentFlags().MarkHidden("default-log-level")
	rootCmd.PersistentFlags().MarkHidden("agent-log-level")
	rootCmd.PersistentFlags().MarkHidden("bpf-event-log-level")
	rootCmd.PersistentFlags().MarkHidden("conntrack-log-level")
	rootCmd.PersistentFlags().MarkHidden("protocol-log-level")
	rootCmd.PersistentFlags().MarkHidden("bpf-verify-log-size")
	rootCmd.PersistentFlags().MarkHidden("kern-perf-event-buffer-size")
	rootCmd.PersistentFlags().MarkHidden("data-perf-event-buffer-size")
	rootCmd.PersistentFlags().MarkHidden("performance-mode")
	rootCmd.PersistentFlags().MarkHidden("conntrack-close-wait-time-mills")
	rootCmd.PersistentFlags().MarkHidden("syscall-perf-event-map-page-num")
	rootCmd.PersistentFlags().MarkHidden("ssl-perf-event-map-page-num")
	rootCmd.PersistentFlags().MarkHidden("conn-perf-event-map-page-num")
	rootCmd.PersistentFlags().MarkHidden("kern-perf-event-map-page-num")
	rootCmd.PersistentFlags().MarkHidden("first-packet-event-map-page-num")

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

func getDefaultCriRuntimeEndpoint() []string {
	var rs []string
	for _, end := range k8s.DefaultRuntimeEndpoints {
		rs = append(rs, strings.TrimPrefix(end, "unix://"))
	}
	return rs
}
