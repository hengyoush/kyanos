package common

import (
	"io"
	"os"
	"time"

	"github.com/jefurry/logrus"
	"github.com/jefurry/logrus/hooks/rotatelog"
)

type Klogger struct {
	*logrus.Logger
}

/**
type LogOptionsSetter interface {
	SetOutput(io.Writer)
	SetPrefix(string)
}**/

func (k *Klogger) SetOutput(w io.Writer) {
	k.SetOut(w)
}

func (k *Klogger) SetPrefix(p string) {

}

var DefaultLog *Klogger = &Klogger{logrus.New()}
var AgentLog *Klogger = &Klogger{logrus.New()}
var BPFLog *Klogger = &Klogger{logrus.New()}

var BPFEventLog *Klogger = &Klogger{logrus.New()}
var UprobeLog *Klogger = &Klogger{logrus.New()}
var ConntrackLog *Klogger = &Klogger{logrus.New()}
var ProtocolParserLog *Klogger = &Klogger{logrus.New()}

var Loggers []*Klogger = []*Klogger{DefaultLog, AgentLog, BPFLog, BPFEventLog, UprobeLog, ConntrackLog, ProtocolParserLog}
var SetLogToFileFlag = false

func SetLogToFile() {
	if SetLogToFileFlag {
		return
	}
	SetLogToFileFlag = true
	for _, l := range Loggers {
		l.SetOut(io.Discard)
		logdir := "/tmp"
		if logdir != "" {
			hook, err := rotatelog.NewHook(
				logdir+"/kyanos.log.%Y%m%d",
				rotatelog.WithMaxAge(time.Hour*24),
				rotatelog.WithRotationTime(time.Hour),
			)
			if err == nil {
				l.Hooks.Add(hook)
			}
		}
	}
}

func SetLogToStdout() {
	SetLogToFileFlag = false
	for _, l := range Loggers {
		// 设置为stdout
		l.SetOut(os.Stdout)
	}
}
