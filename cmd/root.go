package cmd

import (
	"eapm-ebpf/agent"
	"eapm-ebpf/common"
	"fmt"
	"os"
	"time"

	"github.com/jefurry/logrus"
	"github.com/jefurry/logrus/hooks/rotatelog"
	"github.com/sevlyar/go-daemon"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logger *logrus.Logger = common.Log

var rootCmd = &cobra.Command{
	Use:   "eapm-ebpf",
	Short: "eapm-ebpf is an eBPF agent of eAPM",
	Long:  `An easy to use extension of famous apm system, gain the ability of inspect network latency`,
	Run: func(cmd *cobra.Command, args []string) {
		initLog()
		logger.Println("run eAPM eBPF Agent ...")
		logger.Printf("collector-addr: %s\n", viper.GetString(common.CollectorAddrVarName))
		if viper.GetBool(common.DaemonVarName) {
			cntxt := &daemon.Context{
				PidFileName: "./eapm-ebpf.pid",
				PidFilePerm: 0644,
				LogFileName: "./eapm-ebpf.log",
				LogFilePerm: 0640,
				WorkDir:     "./",
				// Umask:       027,
				Args: nil, // use current os args
			}
			d, err := cntxt.Reborn()
			if err != nil {
				logger.Fatal("Unable to run: ", err)
			}
			if d != nil {
				logger.Println("eAPM eBPF agent started!")
				return
			}
			defer cntxt.Release()
			logger.Println("----------------------")
			logger.Println("eAPM eBPF agent started!")
			agent.SetupAgent()
		} else {
			initLog()
			agent.SetupAgent()
		}
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
	rootCmd.Flags().StringVar(&LogDir, "log-dir", "", "log file dir")
	rootCmd.Flags().BoolVarP(&ConsoleOutput, "console-output", "c", true, "print trace data to console")
	rootCmd.Flags().BoolVarP(&Verbose, "verbose", "v", false, "print verbose log")
	rootCmd.Flags().BoolVarP(&Daemon, "daemon", "d", false, "run in background")
	rootCmd.Flags().Int64VarP(&FilterPid, "pid", "p", -1, "the pid to filter")
	rootCmd.Flags().StringSliceVarP(&RemotePorts, "remote-ports", "", []string{}, "specify remote ports to trace, default trace all")
	rootCmd.Flags().StringSliceVarP(&LocalPorts, "local-ports", "", []string{}, "specify local ports to trace, default trace all")
	rootCmd.Flags().StringSliceVarP(&RemoteIps, "remote-ips", "", []string{}, "specify remote ips to trace, default trace all")
	viper.BindPFlags(rootCmd.Flags())
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
