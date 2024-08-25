package stat

import (
	"kyanos/agent/conn"
	"kyanos/agent/protocol"
	"kyanos/common"

	"github.com/jefurry/logrus"
)

var log *logrus.Logger = common.Log

type StatRecorder struct {
	recordMap map[uint64]*StatRecord
}

func InitStatRecorder() *StatRecorder {
	sr := new(StatRecorder)
	sr.recordMap = make(map[uint64]*StatRecord)
	return sr
}

// 每个conn要有一些统计，简单先统计avg
type StatRecord struct {
	avg   float64
	total uint64
	count uint64
	max   uint64
}

func (s *StatRecorder) ReceiveRecord(r protocol.Record, conn *conn.Connection4) error {
	record, ok := s.recordMap[conn.TgidFd]
	if !ok {
		s.recordMap[conn.TgidFd] = new(StatRecord)
		record = s.recordMap[conn.TgidFd]
	}
	// ns or ms?
	record.total += r.Duration
	record.count++
	record.avg = float64(record.total) / float64(record.count)
	if record.max < r.Duration {
		record.max = r.Duration
	}
	log.Infof("%s cur avg: %f, count: %d, max: %d\nreq: %s\nresp: %s", conn.ToString(),
		record.avg, record.count, record.max, r.Request.FormatRawBufToString(), r.Response.FormatRawBufToString())
	log.Infof("req time detail: \n" + r.Request.ExportTimeDetails())
	log.Infof("network time detail: \n" + r.Request.ExportReqRespTimeDetails(r.Response))
	log.Infof("resp time detail: \n" + r.Response.ExportTimeDetails())

	return nil
}

func (s *StatRecorder) RemoveRecord(tgidFd uint64) {
	delete(s.recordMap, tgidFd)
}
