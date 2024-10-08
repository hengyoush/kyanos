package common

import "github.com/jefurry/logrus"

var DefaultLog *logrus.Logger = logrus.New()
var AgentLog *logrus.Logger = logrus.New()
var BPFLog *logrus.Logger = logrus.New()

var BPFEventLog *logrus.Logger = logrus.New()
var UprobeLog *logrus.Logger = logrus.New()
var ConntrackLog *logrus.Logger = logrus.New()
var ProtocolParserLog *logrus.Logger = logrus.New()
