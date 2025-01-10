package common

import (
	"encoding/json"
)

type MetadataReqTopic struct {
	TopicID string `json:"topic_id"`
	Name    string `json:"name"`
}

func (m MetadataReqTopic) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

type MetadataReq struct {
	Topics                             []MetadataReqTopic `json:"topics"`
	AllowAutoTopicCreation             bool               `json:"allow_auto_topic_creation"`
	IncludeClusterAuthorizedOperations bool               `json:"include_cluster_authorized_operations"`
	IncludeTopicAuthorizedOperations   bool               `json:"include_topic_authorized_operations"`
}

func (m MetadataReq) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}
