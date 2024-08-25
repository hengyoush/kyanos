package cmd

import (
	"fmt"
	"kyanos/agent"
	"kyanos/common"
	"os"
	"time"

	"github.com/jefurry/logrus"
	"github.com/jefurry/logrus/hooks/rotatelog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logger *logrus.Logger = common.Log

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
var Verbose bool
var Daemon bool
var Debug bool
var FilterPid int64
var RemotePorts []string
var LocalPorts []string
var RemoteIps []string
var LocalIps []string

func init() {
	// rootCmd.PersistentFlags().StringVar(&LogDir, "log-dir", "", "log file dir")
	// rootCmd.PersistentFlags().BoolVar(&Daemon, "daemon", false, "run in background")
	rootCmd.PersistentFlags().Int64VarP(&FilterPid, "pid", "p", 0, "specify pid to trace, default trace all process")
	rootCmd.PersistentFlags().StringSliceVarP(&RemotePorts, common.RemotePortsVarName, "", []string{}, "specify remote ports to trace, default trace all")
	rootCmd.PersistentFlags().StringSliceVarP(&LocalPorts, common.LocalPortsVarName, "", []string{}, "specify local ports to trace, default trace all")
	rootCmd.PersistentFlags().StringSliceVarP(&RemoteIps, common.RemoteIpsVarName, "", []string{}, "specify remote ips to trace, default trace all")
	rootCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "print more logs helpful to debug")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "print verbose message")
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

func initLog() {
	if viper.GetBool(common.VerboseVarName) {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	logger.SetOut(os.Stdout)

	logdir := viper.GetString(common.LogDirVarName)
	if logdir != "" {
		hook, err := rotatelog.NewHook(
			logdir+"/kyanos.log.%Y%m%d",
			rotatelog.WithMaxAge(time.Hour*24),
			rotatelog.WithRotationTime(time.Hour),
		)
		if err == nil {
			logger.Hooks.Add(hook)
		}
	}
}
