package cmd

import (
	"eapm-ebpf/agent"
	"eapm-ebpf/common"
	"fmt"
	"log"

	"github.com/sevlyar/go-daemon"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "eapm-ebpf",
	Short: "eapm-ebpf is an eBPF agent of eAPM",
	Long:  `An easy to use extension of famous apm system, gain the ability of inspect network latency`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("run eAPM eBPF Agent ...")
		log.Printf("collector-addr: %s\n", viper.GetString(common.CollectorAddrVarName))
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
				log.Fatal("Unable to run: ", err)
			}
			if d != nil {
				log.Println("eAPM eBPF agent started!")
				return
			}
			defer cntxt.Release()
			log.Println("----------------------")
			log.Println("eAPM eBPF agent started!")
			agent.SetupAgent()
		} else {
			agent.SetupAgent()
		}
	},
}

var CollectorAddr string
var LocalMode bool
var ConsoleOutput bool
var Verbose bool
var Daemon bool

func init() {
	rootCmd.Flags().StringVar(&CollectorAddr, "collector-addr", "localhost:18800", "backend collector address")
	rootCmd.Flags().BoolVar(&LocalMode, "local-mode", false, "set true then do not export data to collector")
	rootCmd.Flags().BoolVarP(&ConsoleOutput, "console-output", "c", true, "print trace data to console")
	rootCmd.Flags().BoolVarP(&Verbose, "verbose", "v", true, "print verbose log")
	rootCmd.Flags().BoolVarP(&Daemon, "daemon", "d", false, "run in background")
	viper.BindPFlags(rootCmd.Flags())
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
