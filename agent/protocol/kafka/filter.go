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
	pass := true
	pass = pass && (len(k.apiKey) == 0 || containsAPIKey(k.apiKey, req.(*Request).Apikey))
	if k.topic != "" && pass {
		kafkaReq, ok := req.(*Request)
		if !ok {
			return false
		}
		if kafkaReq.Apikey == KProduce {
			if k.producer && kafkaReq.OriginReq != nil {
				originProduceReq := kafkaReq.OriginReq.(ProduceReq)
				matched := false
				for _, topic := range originProduceReq.Topics {
					if topic.Name == k.topic {
						matched = true
						break
					}
				}
				if len(originProduceReq.Topics) == 0 || !matched {
					pass = false
				}
			} else {
				pass = false
			}
		} else if kafkaReq.Apikey == KFetch {
			kafkaResp, ok := resp.(*Response)
			if !ok {
				return false
			}
			if k.consumer && kafkaResp.OriginResp != nil {
				originFetchResp := kafkaResp.OriginResp.(FetchResp)
				matched := false
				for _, topic := range originFetchResp.Topics {
					if topic.Name == k.topic {
						matched = true
						break
					}
				}
				if len(originFetchResp.Topics) == 0 || !matched {
					pass = false
				}
			} else {
				pass = false
			}
		} else {
			pass = false
		}
	}
	return pass
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
	return len(k.apiKey) == 0 || (k.producer && k.topic != "")
}

func (k *KafkaFilter) FilterByResponse() bool {
	return (k.consumer && k.topic != "")
}

func (KafkaFilter) Protocol() bpf.AgentTrafficProtocolT {
	return bpf.AgentTrafficProtocolTKProtocolKafka
}

var _ protocol.ProtocolFilter = &KafkaFilter{}
