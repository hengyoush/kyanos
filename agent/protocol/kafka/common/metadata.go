package common

import (
	"encoding/json"
	"reflect"
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

func vectorsEqual[T any](lhs, rhs []T) bool {
	return len(lhs) == len(rhs) && reflect.DeepEqual(lhs, rhs)
}

func (lhs MetadataReqTopic) Equal(rhs MetadataReqTopic) bool {
	return lhs.TopicID == rhs.TopicID && lhs.Name == rhs.Name
}

func (lhs MetadataReq) Equal(rhs MetadataReq) bool {
	return lhs.AllowAutoTopicCreation == rhs.AllowAutoTopicCreation &&
		lhs.IncludeClusterAuthorizedOperations == rhs.IncludeClusterAuthorizedOperations &&
		lhs.IncludeTopicAuthorizedOperations == rhs.IncludeTopicAuthorizedOperations &&
		vectorsEqual(lhs.Topics, rhs.Topics)
}
