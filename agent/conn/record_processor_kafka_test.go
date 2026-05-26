package conn

import (
	"testing"

	"kyanos/agent/protocol"
	"kyanos/agent/protocol/kafka"
	kcommon "kyanos/agent/protocol/kafka/common"
	"kyanos/bpf"

	"github.com/stretchr/testify/assert"
)

func TestSubmitRecord_KafkaConsumerTopicFilterSubmitsMatchingFetch(t *testing.T) {
	oldRecordFunc := RecordFunc
	defer func() { RecordFunc = oldRecordFunc }()

	submitted := false
	RecordFunc = func(record protocol.Record, c *Connection4) error {
		submitted = true
		return nil
	}

	conn := &Connection4{
		Protocol:        bpf.AgentTrafficProtocolTKProtocolKafka,
		protocolParsers: make(map[bpf.AgentTrafficProtocolT]protocol.ProtocolStreamParser),
		MessageFilter:   kafka.NewKafkaFilter(nil, "orders", false, true),
	}
	record := protocol.NewRecord(
		&kcommon.Request{Apikey: kcommon.KFetch},
		&kcommon.Response{
			OriginResp: kcommon.FetchResp{
				Topics: []kcommon.FetchRespTopic{{Name: "orders"}},
			},
		},
	)

	submitRecord(*record, conn)

	assert.True(t, submitted)
}

func TestSubmitRecord_KafkaTopicFilterRejectsWhenNoDirectionEnabled(t *testing.T) {
	oldRecordFunc := RecordFunc
	defer func() { RecordFunc = oldRecordFunc }()

	submitted := false
	RecordFunc = func(record protocol.Record, c *Connection4) error {
		submitted = true
		return nil
	}

	conn := &Connection4{
		Protocol:        bpf.AgentTrafficProtocolTKProtocolKafka,
		protocolParsers: make(map[bpf.AgentTrafficProtocolT]protocol.ProtocolStreamParser),
		MessageFilter:   kafka.NewKafkaFilter(nil, "orders", false, false),
	}
	record := protocol.NewRecord(
		&kcommon.Request{
			Apikey: kcommon.KProduce,
			OriginReq: kcommon.ProduceReq{
				Topics: []kcommon.ProduceReqTopic{{Name: "orders"}},
			},
		},
		&kcommon.Response{},
	)

	submitRecord(*record, conn)

	assert.False(t, submitted)
}
