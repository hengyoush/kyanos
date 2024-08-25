package cmd

import (
	"eapm-ebpf/agent"
	"eapm-ebpf/common"
	"fmt"
	"os"
	"time"

	"github.com/jefurry/logrus"
	"github.com/jefurry/logrus/hooks/rotatelog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logger *logrus.Logger = common.Log

var rootCmd = &cobra.Command{
	Use:   "eapm-ebpf",
	Short: "eapm-ebpf is an eBPF agent of eAPM",
	Long:  `An easy to use extension of famous apm system, gain the ability of inspect network latency`,
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	Run: func(cmd *cobra.Command, args []string) {
		startAgent(agent.AgentOptions{})
	},
}

var CollectorAddr string
var LocalMode bool
var ConsoleOutput bool
var Verbose bool
var Daemon bool
var LogDir string
var FilterPid int64
var RemotePorts []string
var LocalPorts []string
var RemoteIps []string
var LocalIps []string

func init() {
	rootCmd.PersistentFlags().StringVar(&LogDir, "log-dir", "", "log file dir")
	rootCmd.Flags().BoolVarP(&ConsoleOutput, "console-output", "c", true, "print trace data to console")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "print verbose log")
	rootCmd.PersistentFlags().BoolVarP(&Daemon, "daemon", "d", false, "run in background")
	rootCmd.PersistentFlags().Int64VarP(&FilterPid, "pid", "p", -1, "the pid to filter")
	rootCmd.PersistentFlags().StringSliceVarP(&RemotePorts, "remote-ports", "", []string{}, "specify remote ports to trace, default trace all")
	rootCmd.PersistentFlags().StringSliceVarP(&LocalPorts, "local-ports", "", []string{}, "specify local ports to trace, default trace all")
	rootCmd.PersistentFlags().StringSliceVarP(&RemoteIps, "remote-ips", "", []string{}, "specify remote ips to trace, default trace all")
	viper.BindPFlags(rootCmd.Flags())
	viper.BindPFlags(rootCmd.PersistentFlags())
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

func initLog() {
	if viper.GetBool(common.VerboseVarName) {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	if viper.GetBool(common.ConsoleOutputVarName) {
		logger.SetOut(os.Stdout)
	}

	logdir := viper.GetString(common.LogDirVarName)
	if logdir != "" {
		hook, err := rotatelog.NewHook(
			logdir+"/eapm-ebpf.log.%Y%m%d",
			rotatelog.WithMaxAge(time.Hour*24),
			rotatelog.WithRotationTime(time.Hour),
		)
		if err == nil {
			logger.Hooks.Add(hook)
		}
	}
}
