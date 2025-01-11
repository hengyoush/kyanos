package common

import (
	"fmt"
	"kyanos/agent/protocol"
)

// API Keys (opcodes)
// Before each request is sent, the client sends the API key and the API version.These two 16-bit
// numbers, when taken together, uniquely identify the schema of the message to follow.
// https://kafka.apache.org/protocol.html#protocol_api_keys
// Mapping from Kafka version to API Version
// https://cwiki.apache.org/confluence/display/KAFKA/Kafka+APIs
type APIKey int16

const (
	KProduce APIKey = iota
	KFetch
	KListOffsets
	KMetadata
	KLeaderAndIsr
	KStopReplica
	KUpdateMetadata
	KControlledShutdown
	KOffsetCommit
	KOffsetFetch
	KFindCoordinator
	KJoinGroup
	KHeartbeat
	KLeaveGroup
	KSyncGroup
	KDescribeGroups
	KListGroups
	KSaslHandshake
	KApiVersions
	KCreateTopics
	KDeleteTopics
	KDeleteRecords
	KInitProducerId
	KOffsetForLeaderEpoch
	KAddPartitionsToTxn
	KAddOffsetsToTxn
	KEndTxn
	KWriteTxnMarkers
	KTxnOffsetCommit
	KDescribeAcls
	KCreateAcls
	KDeleteAcls
	KDescribeConfigs
	KAlterConfigs
	KAlterReplicaLogDirs
	KDescribeLogDirs
	KSaslAuthenticate
	KCreatePartitions
	KCreateDelegationToken
	KReneDelegationToken
	KExpireDelegationToken
	KDescribeDelegationToken
	KDeleteGroups
	KElectLeaders
	KIncrementalAlterConfigs
	KAlterPartitionReassignments
	KListPartitionReassignments
	KOffsetDelete
	KDescribeClientQuotas
	KAlterClientQuotas
	KDescribeUserScramCredentials
	KAlterUserScramCredentials
	_ // Placeholder for 52-55
	_ // Placeholder for 52-55
	_ // Placeholder for 52-55
	_ // Placeholder for 52-55
	KAlterIsr
	KUpdateFeatures
	_ // Placeholder for 58-59
	_ // Placeholder for 58-59
	KDescribeCluster
	KDescribeProducers
)

type ErrorCode int16

const (
	KUnknownServerError                 ErrorCode = -1
	KNone                               ErrorCode = 0
	KOffsetOutOfRange                   ErrorCode = 1
	KCorruptMessage                     ErrorCode = 2
	KUnknownTopicOrPartitiov            ErrorCode = 3
	KInvalidFetchSize                   ErrorCode = 4
	KLeaderNotAvailable                 ErrorCode = 5
	KNotLeaderOrFollowee                ErrorCode = 6
	KRequestTimedOut                    ErrorCode = 7
	KBrokerNotAvailable                 ErrorCode = 8
	KReplicaNotAvailable                ErrorCode = 9
	KMessageTooLarge                    ErrorCode = 10
	KStaleControllerEpoch               ErrorCode = 11
	KOffsetMetadataTooLarge             ErrorCode = 12
	KNetworkException                   ErrorCode = 13
	KCoordinatorLoadInProgress          ErrorCode = 14
	KCoordinatorNotAvailable            ErrorCode = 15
	KNotCoordinator                     ErrorCode = 16
	KInvalidTopicException              ErrorCode = 17
	KRecordListTooLarge                 ErrorCode = 18
	KNotEnoughReplicas                  ErrorCode = 19
	KNotEnoughReplicasAfterAppend       ErrorCode = 20
	KInvalidRequiredAcks                ErrorCode = 21
	KIllegalGeneration                  ErrorCode = 22
	KInconsistentGroupProtocol          ErrorCode = 23
	KInvalidGroupID                     ErrorCode = 24
	KUnknownMemberID                    ErrorCode = 25
	KInvalidSessionTimeout              ErrorCode = 26
	KRebalanceInProgress                ErrorCode = 27
	KInvalidCommitOffsetSize            ErrorCode = 28
	KTopicAuthorizationFailed           ErrorCode = 29
	KGroupAuthorizationFailed           ErrorCode = 30
	KClusterAuthorizationFailed         ErrorCode = 31
	KInvalidTimestamp                   ErrorCode = 32
	KUnsupportedSaslMechanism           ErrorCode = 33
	KIllegalSaslState                   ErrorCode = 34
	KUnsupportedVersion                 ErrorCode = 35
	KTopicAlreadyExists                 ErrorCode = 36
	KInvalidPartitions                  ErrorCode = 37
	KInvalidReplicationFactor           ErrorCode = 38
	KInvalidReplicaAssignment           ErrorCode = 39
	KInvalidConfig                      ErrorCode = 40
	KNotController                      ErrorCode = 41
	KInvalidRequest                     ErrorCode = 42
	KUnsupportedForMessageFormat        ErrorCode = 43
	KPolicyViolation                    ErrorCode = 44
	KOutOfOrderSequenceNumber           ErrorCode = 45
	KDuplicateSequenceNumber            ErrorCode = 46
	KInvalidProducerEpoch               ErrorCode = 47
	KInvalidTxnState                    ErrorCode = 48
	KInvalidProducerIDMapping           ErrorCode = 49
	KInvalidTransactionTimeout          ErrorCode = 50
	KConcurrentTransactions             ErrorCode = 51
	KTransactionCoordinatorFenced       ErrorCode = 52
	KTransactionalIDAuthorizationFailed ErrorCode = 53
	KSecurityDisabled                   ErrorCode = 54
	KOperationNotAttempted              ErrorCode = 55
	KKafkaStorageError                  ErrorCode = 56
	KLogDirNotFound                     ErrorCode = 57
	KSaslAuthenticationFailed           ErrorCode = 58
	KUnknownProducerID                  ErrorCode = 59
	KReassignmentInProgress             ErrorCode = 60
	KDelegationTokenAuthDisabled        ErrorCode = 61
	KDelegationTokenNotFound            ErrorCode = 62
	KDelegationTokenOwnerMismatch       ErrorCode = 63
	KDelegationTokenRequestNotAllowed   ErrorCode = 64
	KDelegationTokenAuthorizationFailed ErrorCode = 65
	KDelegationTokenExpired             ErrorCode = 66
	KInvalidPrincipalType               ErrorCode = 67
	KNonEmptyGroup                      ErrorCode = 68
	KGroupIDNotFound                    ErrorCode = 69
	KFetchSessionIDNotFound             ErrorCode = 70
	KInvalidFetchSessionEpoch           ErrorCode = 71
	KListenerNotFound                   ErrorCode = 72
	KTopicDeletionDisabled              ErrorCode = 73
	KFencedLeaderEpoch                  ErrorCode = 74
	KUnknownLeaderEpoch                 ErrorCode = 75
	KUnsupportedCompressionType         ErrorCode = 76
	KStaleBrokerEpoch                   ErrorCode = 77
	KOffsetNotAvailable                 ErrorCode = 78
	KMemberIDRequired                   ErrorCode = 79
	KPreferredLeaderNotAvailable        ErrorCode = 80
	KGroupMaxSizeReached                ErrorCode = 81
	KFencedInstanceID                   ErrorCode = 82
	KEligibleLeadersNotAvailable        ErrorCode = 83
	KElectionNotNeeded                  ErrorCode = 84
	KNoReassignmentInProgress           ErrorCode = 85
	KGroupSubscribedToTopic             ErrorCode = 86
	KInvalidRecord                      ErrorCode = 87
	KUnstableOffsetCommit               ErrorCode = 88
	KThrottlingQuotaExceeded            ErrorCode = 89
	KProducerFenced                     ErrorCode = 90
	KResourceNotFound                   ErrorCode = 91
	KDuplicateResource                  ErrorCode = 92
	KUnacceptableCredential             ErrorCode = 93
	KInconsistentVoterSet               ErrorCode = 94
	KInvalidUpdateVersion               ErrorCode = 95
	KFeatureUpdateFailed                ErrorCode = 96
	KPrincipalDeserializationFailure    ErrorCode = 97
	KSnapshotNotFound                   ErrorCode = 98
	KPositionOutOfRange                 ErrorCode = 99
	KUnknownTopicID                     ErrorCode = 100
	KDuplicateBrokerRegistration        ErrorCode = 101
	KBrokerIDNotRegistered              ErrorCode = 102
	KInconsistentTopicID                ErrorCode = 103
	KInconsistentClusterID              ErrorCode = 104
)

type APIVersionData struct {
	MinVersion      int16
	MaxVersion      int16
	FlexibleVersion int16
}

// A mapping of api_key to the api_versions supported and the version from which it becomes
// flexible. Flexible versions use tagged fields and more efficient serialization for
// variable-length objects.
// https://cwiki.apache.org/confluence/display/KAFKA/KIP-482%3A+The+Kafka+Protocol+should+Support+Optional+Tagged+Fields#KIP482:TheKafkaProtocolshouldSupportOptionalTaggedFields-FlexibleVersions
// Detailed information on each API key:
// https://github.com/apache/kafka/tree/trunk/clients/src/main/resources/common/message
// TODO(chengruizhe): Needs updating for new opcodes.
var APIVersionMap = map[APIKey]APIVersionData{
	// Setting min supported version to 1 to help finding frame boundary.
	KProduce:                      {1, 9, 9},
	KFetch:                        {0, 12, 12},
	KListOffsets:                  {0, 7, 6},
	KMetadata:                     {0, 12, 9},
	KLeaderAndIsr:                 {0, 5, 4},
	KStopReplica:                  {0, 3, 2},
	KUpdateMetadata:               {0, 7, 6},
	KControlledShutdown:           {0, 3, 3},
	KOffsetCommit:                 {0, 8, 8},
	KOffsetFetch:                  {0, 8, 6},
	KFindCoordinator:              {0, 4, 3},
	KJoinGroup:                    {0, 7, 6},
	KHeartbeat:                    {0, 4, 4},
	KLeaveGroup:                   {0, 4, 4},
	KSyncGroup:                    {0, 5, 4},
	KDescribeGroups:               {0, 5, 5},
	KListGroups:                   {0, 4, 3},
	KSaslHandshake:                {0, 1, -1},
	KApiVersions:                  {0, 3, 3},
	KCreateTopics:                 {0, 7, 5},
	KDeleteTopics:                 {0, 6, 4},
	KDeleteRecords:                {0, 2, 2},
	KInitProducerId:               {0, 4, 2},
	KOffsetForLeaderEpoch:         {0, 4, 4},
	KAddPartitionsToTxn:           {0, 3, 3},
	KAddOffsetsToTxn:              {0, 3, 3},
	KEndTxn:                       {0, 3, 3},
	KWriteTxnMarkers:              {0, 1, 1},
	KTxnOffsetCommit:              {0, 3, 3},
	KDescribeAcls:                 {0, 2, 2},
	KCreateAcls:                   {0, 2, 2},
	KDeleteAcls:                   {0, 2, 2},
	KDescribeConfigs:              {0, 4, 4},
	KAlterConfigs:                 {0, 2, 2},
	KAlterReplicaLogDirs:          {0, 2, 2},
	KDescribeLogDirs:              {0, 2, 2},
	KSaslAuthenticate:             {0, 2, 2},
	KCreatePartitions:             {0, 3, 2},
	KCreateDelegationToken:        {0, 2, 2},
	KReneDelegationToken:          {0, 2, 2},
	KExpireDelegationToken:        {0, 2, 2},
	KDescribeDelegationToken:      {0, 2, 2},
	KDeleteGroups:                 {0, 5, 5},
	KElectLeaders:                 {0, 2, 2},
	KIncrementalAlterConfigs:      {0, 1, 1},
	KAlterPartitionReassignments:  {0, 0, 0},
	KListPartitionReassignments:   {0, 0, 0},
	KOffsetDelete:                 {0, 0, -1},
	KDescribeClientQuotas:         {0, 1, 1},
	KAlterClientQuotas:            {0, 1, 1},
	KDescribeUserScramCredentials: {0, 0, 0},
	KAlterUserScramCredentials:    {0, 0, 0},
	KAlterIsr:                     {0, 0, 0},
	KUpdateFeatures:               {0, 0, 0},
	KDescribeCluster:              {0, 0, 0},
	KDescribeProducers:            {0, 0, 0},
}

func IsFlexible(apiKey APIKey, apiVersion int16) bool {
	if versionData, ok := APIVersionMap[apiKey]; ok {
		// Negative flexible version indicates that there's no flexible version for this api key.
		if versionData.FlexibleVersion < 0 {
			return false
		}
		return apiVersion >= versionData.FlexibleVersion
	}
	return false
}

func IsValidAPIKey(apiKey int16) bool {
	_, ok := APIVersionMap[APIKey(apiKey)]
	return ok
}

func IsSupportedAPIVersion(apiKey APIKey, apiVersion int16) bool {
	if versionData, ok := APIVersionMap[apiKey]; ok {
		return apiVersion >= versionData.MinVersion && apiVersion <= versionData.MaxVersion
	}
	return false
}

const (
	KMessageLengthBytes  int32 = 4
	KAPIKeyLength        int32 = 2
	KAPIVersionLength    int32 = 2
	KCorrelationIDLength int32 = 4
	KMinReqPacketLength  int32 = KMessageLengthBytes + KAPIKeyLength + KAPIVersionLength + KCorrelationIDLength
	KMinRespPacketLength int32 = KMessageLengthBytes + KCorrelationIDLength
	KMaxAPIVersion       int32 = 12
)

var _ protocol.ParsedMessage = &Packet{}
var _ protocol.ParsedMessage = &Request{}
var _ protocol.ParsedMessage = &Response{}

type Packet struct {
	protocol.FrameBase
	CorrelationID int32
	Msg           string
	Consumed      bool
	isReq         bool
}

type Request struct {
	protocol.FrameBase
	Apikey     APIKey
	ApiVersion int16
	ClientId   string
	Msg        string
}

type Response struct {
	protocol.FrameBase
	Msg string
}

func (p *Packet) FormatToString() string {
	return fmt.Sprintf("[FrameBase: %s] %s", p.FrameBase.String(), p.Msg)
}

func (p *Packet) IsReq() bool {
	return p.isReq
}

func (p *Packet) SetIsReq(isReq bool) {
	p.isReq = isReq
}

func (p *Packet) StreamId() protocol.StreamId {
	return 0
}

func (r *Request) FormatToString() string {
	panic("unimplemented")
}

func (r *Request) IsReq() bool {
	return true
}

func (r *Request) StreamId() protocol.StreamId {
	return 0
}

func (r *Response) FormatToString() string {
	panic("unimplemented")
}

func (r *Response) IsReq() bool {
	return false
}

func (r *Response) StreamId() protocol.StreamId {
	return 0
}
