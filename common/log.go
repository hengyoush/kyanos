package common

import (
	"io"

	"github.com/jefurry/logrus"
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
