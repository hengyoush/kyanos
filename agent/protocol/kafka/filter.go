package kafka

import (
	"kyanos/agent/protocol"
	. "kyanos/agent/protocol/kafka/common"
	"kyanos/bpf"
)

type KafkaFilter struct {
	apiKey   []APIKey
	topic    string
	producer bool
	consumer bool
}

func NewKafkaFilter(apiKey []int32, topic string, producer bool, consumer bool) *KafkaFilter {
	apiKeys := make([]APIKey, len(apiKey))
	for i, key := range apiKey {
		apiKeys[i] = APIKey(key)
	}

	return &KafkaFilter{
		apiKey:   apiKeys,
		topic:    topic,
		producer: producer,
		consumer: consumer,
	}
}

func (k *KafkaFilter) Filter(req protocol.ParsedMessage, resp protocol.ParsedMessage) bool {
	kafkaReq, ok := req.(*Request)
	if !ok {
		return false
	}
	if len(k.apiKey) > 0 && !containsAPIKey(k.apiKey, kafkaReq.Apikey) {
		return false
	}
	if k.topic == "" {
		return true
	}
	if kafkaReq.Apikey == KProduce {
		if !k.producer || kafkaReq.OriginReq == nil {
			return false
		}
		originProduceReq := kafkaReq.OriginReq.(ProduceReq)
		for _, topic := range originProduceReq.Topics {
			if topic.Name == k.topic {
				return true
			}
		}
		return false
	}
	if kafkaReq.Apikey == KFetch {
		if !k.consumer {
			return false
		}
		kafkaResp, ok := resp.(*Response)
		if !ok || kafkaResp.OriginResp == nil {
			return false
		}
		originFetchResp := kafkaResp.OriginResp.(FetchResp)
		for _, topic := range originFetchResp.Topics {
			if topic.Name == k.topic {
				return true
			}
		}
		return false
	}
	return false
}

func containsAPIKey(apiKeys []APIKey, key APIKey) bool {
	for _, apiKey := range apiKeys {
		if apiKey == key {
			return true
		}
	}
	return false
}

func (k *KafkaFilter) FilterByProtocol(p bpf.AgentTrafficProtocolT) bool {
	return p == bpf.AgentTrafficProtocolTKProtocolKafka
}

func (k *KafkaFilter) FilterByRequest() bool {
	return len(k.apiKey) > 0 || k.topic != ""
}

func (k *KafkaFilter) FilterByResponse() bool {
	return k.consumer && k.topic != ""
}

func (KafkaFilter) Protocol() bpf.AgentTrafficProtocolT {
	return bpf.AgentTrafficProtocolTKProtocolKafka
}

var _ protocol.ProtocolFilter = &KafkaFilter{}
