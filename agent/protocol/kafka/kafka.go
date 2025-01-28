package kafka

import (
	"errors"
	"kyanos/agent/buffer"
	"kyanos/agent/protocol"
	"kyanos/agent/protocol/kafka/common"
	"kyanos/agent/protocol/kafka/decoder"
	"kyanos/bpf"
	kc "kyanos/common"
)

func init() {
	protocol.ParsersMap[bpf.AgentTrafficProtocolTKProtocolKafka] = func() protocol.ProtocolStreamParser {
		return &KafkaStreamParser{
			correlationIdMap: make(map[int32]struct{}),
		}
	}
}

func (k *KafkaStreamParser) FindBoundary(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType, startPos int) int {
	var minLength int32
	buf := streamBuffer.Head().Buffer()
	if messageType == protocol.Request {
		minLength = common.KMinReqPacketLength
	} else {
		minLength = common.KMinRespPacketLength
	}
	if len(buf) < int(minLength) {
		return -1
	}

	for i := startPos; i < len(buf)-int(minLength); i++ {
		curBuf := buf[i:]
		binaryDecoder := protocol.NewBinaryDecoder(curBuf)
		payloadLength, err := protocol.ExtractBEInt[int32](binaryDecoder)
		if err != nil {
			return -1
		}
		if payloadLength <= 0 || payloadLength+common.KMessageLengthBytes > int32(len(curBuf)) {
			continue
		}

		if messageType == protocol.Request {
			requestApiKeyInt, err := protocol.ExtractBEInt[int16](binaryDecoder)
			if err != nil {
				return -1
			}
			if !common.IsValidAPIKey(requestApiKeyInt) {
				continue
			}
			requestApiVersion, err := protocol.ExtractBEInt[int16](binaryDecoder)
			if err != nil {
				return -1
			}
			if !common.IsSupportedAPIVersion(common.APIKey(requestApiKeyInt), requestApiVersion) {
				continue
			}
		}

		correlationId, err := protocol.ExtractBEInt[int32](binaryDecoder)
		if err != nil {
			return -1
		}
		if correlationId < 0 {
			continue
		}
		if messageType == protocol.Response {
			if _, ok := k.correlationIdMap[correlationId]; !ok {
				continue
			}
		} else {
			clientIdLength, err := protocol.ExtractBEInt[int16](binaryDecoder)
			if err != nil {
				continue
			}
			if clientIdLength > 0 {
				clientId, err := binaryDecoder.ExtractString(int(clientIdLength))
				if err != nil {
					continue
				}
				if k.clientId != "" && k.clientId != clientId {
					continue
				}
			} else {
				continue
			}
		}

		return i
	}

	return -1
}

func (k *KafkaStreamParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType) protocol.ParseResult {
	buf := streamBuffer.Head().Buffer()
	var minPacketLength int32
	if messageType == protocol.Request {
		minPacketLength = common.KMinReqPacketLength
	} else {
		minPacketLength = common.KMinRespPacketLength
	}
	if len(buf) < int(minPacketLength) {
		kc.ProtocolParserLog.Debugf("Not enough data for parsing: %v, messageType: %v", len(buf), messageType)
		return protocol.ParseResult{
			ParseState: protocol.NeedsMoreData,
		}
	}
	binaryDecoder := protocol.NewBinaryDecoder(buf)
	payloadLength, err := protocol.ExtractBEInt[int32](binaryDecoder)
	kc.ProtocolParserLog.Debugf("[%v]payloadLength: %v", messageType, payloadLength)
	if err != nil {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	if payloadLength+common.KMessageLengthBytes <= minPacketLength {
		kc.ProtocolParserLog.Debugf("[%v]Invalid payload length: %v + %v <= %v", messageType, payloadLength, common.KMessageLengthBytes, minPacketLength)
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	var requestApiKey common.APIKey
	var requestApiVersion int16
	if messageType == protocol.Request {
		requestApiKeyInt, err := protocol.ExtractBEInt[int16](binaryDecoder)
		if err != nil || !common.IsValidAPIKey(requestApiKeyInt) {
			kc.ProtocolParserLog.Debugf("[%v]Invalid Valid API key: %v", messageType, requestApiKeyInt)
			return protocol.ParseResult{
				ParseState: protocol.Invalid,
			}
		}
		requestApiKey = common.APIKey(requestApiKeyInt)
		requestApiVersion, err = protocol.ExtractBEInt[int16](binaryDecoder)
		if err != nil {
			kc.ProtocolParserLog.Debugf("[%v]Invalid API version: %v", messageType, requestApiVersion)
			return protocol.ParseResult{
				ParseState: protocol.Invalid,
			}
		}
		kc.ProtocolParserLog.Debugf("[%v]API key: %v, API version: %v", messageType, requestApiKey, requestApiVersion)
		if !common.IsSupportedAPIVersion(requestApiKey, requestApiVersion) {
			kc.ProtocolParserLog.Debugf("[%v]Unsupported API version: %v", messageType, requestApiVersion)
			return protocol.ParseResult{
				ParseState: protocol.Invalid,
			}
		}
	}

	correlationId, err := protocol.ExtractBEInt[int32](binaryDecoder)
	if err != nil || correlationId < 0 {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	kc.ProtocolParserLog.Debugf("[%v]correlationId: %v", messageType, correlationId)

	if uint32(len(buf))-uint32(common.KMessageLengthBytes) < uint32(payloadLength) {
		kc.ProtocolParserLog.Debugf("[%v]Not enough data for parsing2: %v - %v < %v", messageType, len(buf), common.KMessageLengthBytes, payloadLength)
		return protocol.ParseResult{
			ParseState: protocol.NeedsMoreData,
		}
	}
	if messageType == protocol.Request {
		k.correlationIdMap[correlationId] = struct{}{}
	}
	msg := buf[common.KMessageLengthBytes : common.KMessageLengthBytes+payloadLength]
	fb, ok := protocol.CreateFrameBase(streamBuffer, uint32(common.KMessageLengthBytes+payloadLength))
	if !ok {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	parseResult := common.Packet{
		FrameBase:     fb,
		CorrelationID: correlationId,
		Msg:           string(msg),
	}
	parseResult.SetIsReq(messageType == protocol.Request)
	kc.ProtocolParserLog.Debugf("[%v]Parsed message success: %v", messageType, parseResult)
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&parseResult},
		ReadBytes:      uint32(common.KMessageLengthBytes + payloadLength),
	}
}

// Match implements protocol.ProtocolStreamParser.
func (k *KafkaStreamParser) Match(reqStreams map[protocol.StreamId]*protocol.ParsedMessageQueue, respStreams map[protocol.StreamId]*protocol.ParsedMessageQueue) []protocol.Record {
	records := make([]protocol.Record, 0)
	errorCnt := 0
	reqStream, ok1 := reqStreams[0]
	respStream, ok2 := respStreams[0]
	if !ok1 || !ok2 || len(*reqStream) == 0 || len(*respStream) == 0 {
		return records
	}
	correlationIdMap := make(map[int32]*common.Packet)
	for _, respMsg := range *respStream {
		correlationIdMap[respMsg.(*common.Packet).CorrelationID] = respMsg.(*common.Packet)
	}

	for _, reqMsg := range *reqStream {
		req := reqMsg.(*common.Packet)
		resp, ok := correlationIdMap[req.CorrelationID]
		if ok {
			r, err := processReqRespPair(req, resp)
			if err == nil {
				records = append(records, *r)
				clientId := r.Req.(*common.Request).ClientId
				if k.clientId == "" && clientId != "" {
					k.clientId = clientId
				}
			} else {
				kc.ProtocolParserLog.Debugf("Error processing req/resp pair: %v", err)
				errorCnt++
			}
			req.Consumed = true
			delete(correlationIdMap, req.CorrelationID)
			delete(k.correlationIdMap, req.CorrelationID)
		}
	}

	// Resp packets left in the map don't have a matched request.
	for _, resp := range correlationIdMap {
		kc.ProtocolParserLog.Debugf("Response packet without a matching request: %v", resp.CorrelationID)
		errorCnt++
	}

	// Clean-up consumed req_packets at the head.
	i := 0
	for ; i < len(*reqStream); i++ {
		if !(*reqStream)[i].(*common.Packet).Consumed {
			break
		}
	}

	if i > 0 {
		*reqStream = (*reqStream)[i:]
	}
	*respStream = (*respStream)[0:0]
	return records
}

func ProcessReq(reqPacket *common.Packet) (*common.Request, error) {
	req := &common.Request{}
	req.FrameBase = reqPacket.FrameBase
	req.SetTimeStamp(reqPacket.TimestampNs())
	decoder := decoder.NewPacketDecoder([]byte(reqPacket.Msg))
	_, err := decoder.ExtractReqHeader(req)
	if err != nil {
		return nil, err
	}
	switch req.Apikey {
	case common.KProduce:
		err = ProcessProduceReq(decoder, req)
	case common.KFetch:
		err = ProcessFetchReq(decoder, req)
	case common.KJoinGroup:
		err = ProcessJoinGroupReq(decoder, req)
	case common.KSyncGroup:
		err = ProcessSyncGroupReq(decoder, req)
	case common.KMetadata:
		err = ProcessMetadataReq(decoder, req)
	default:
		kc.ProtocolParserLog.Infof("Unparsed request API key: %v", req.Apikey)
	}
	return req, err
}

func ProcessResp(respPacket *common.Packet, apiKey common.APIKey, apiversion int16) (*common.Response, error) {
	resp := &common.Response{}
	resp.FrameBase = respPacket.FrameBase
	resp.SetTimeStamp(respPacket.TimestampNs())
	decoder := decoder.NewPacketDecoder([]byte(respPacket.Msg))
	decoder.SetAPIInfo(apiKey, apiversion)
	err := decoder.ExtractRespHeader(resp)
	if err != nil {
		return nil, err
	}
	switch apiKey {
	case common.KProduce:
		err = ProcessProduceResp(decoder, resp)
	case common.KFetch:
		err = ProcessFetchResp(decoder, resp)
	case common.KJoinGroup:
		err = ProcessJoinGroupResp(decoder, resp)
	case common.KSyncGroup:
		err = ProcessSyncGroupResp(decoder, resp)
	default:
		kc.ProtocolParserLog.Infof("Unparsed response API key: %v", apiKey)
		resp.Msg = string(respPacket.Msg)
	}
	return resp, err
}

func processReqRespPair(req *common.Packet, resp *common.Packet) (*protocol.Record, error) {
	if req.TimestampNs() > resp.TimestampNs() {
		kc.ProtocolParserLog.Warnf("Request timestamp is later than response timestamp")
		return nil, errors.New("request timestamp is later than response timestamp")
	}
	r := &protocol.Record{}
	reqMsg, err := ProcessReq(req)
	if err != nil {
		kc.ProtocolParserLog.Infof("Error processing kafka request: %v", err)
		reqMsg.Msg = string(req.Msg)
		// return nil, err
	}
	respMsg, err := ProcessResp(resp, reqMsg.Apikey, reqMsg.ApiVersion)
	if err != nil {
		kc.ProtocolParserLog.Infof("Error processing kafka response: %v", err)
		respMsg.Msg = string(resp.Msg)
		// return nil, err
	}
	r.Req = reqMsg
	r.Resp = respMsg
	return r, nil
}

func ProcessProduceReq(decoder *decoder.PacketDecoder, req *common.Request) error {
	r, err := decoder.ExtractProduceReq()
	if err != nil {
		return err
	}
	jsonData, err := r.ToJSON()
	if err != nil {
		return err
	}
	req.Msg = string(jsonData)
	req.OriginReq = r
	return nil
}

func ProcessProduceResp(decoder *decoder.PacketDecoder, resp *common.Response) error {
	r, err := decoder.ExtractProduceResp()
	if err != nil {
		return err
	}
	jsonData, err := r.ToJSON()
	if err != nil {
		return err
	}
	resp.Msg = string(jsonData)
	resp.OriginResp = r
	return nil
}

func ProcessFetchReq(decoder *decoder.PacketDecoder, req *common.Request) error {
	r, err := decoder.ExtractFetchReq()
	if err != nil {
		return err
	}
	jsonData, err := r.ToJSON()
	if err != nil {
		return err
	}
	req.Msg = string(jsonData)
	req.OriginReq = r
	return nil
}

func ProcessFetchResp(decoder *decoder.PacketDecoder, resp *common.Response) error {
	r, err := decoder.ExtractFetchResp()
	if err != nil {
		return err
	}
	jsonData, err := r.ToJSON()
	if err != nil {
		return err
	}
	resp.Msg = string(jsonData)
	resp.OriginResp = r
	return nil
}

func ProcessJoinGroupReq(decoder *decoder.PacketDecoder, req *common.Request) error {
	r, err := decoder.ExtractJoinGroupReq()
	if err != nil {
		return err
	}
	jsonData, err := r.ToJSON()
	if err != nil {
		return err
	}
	req.Msg = string(jsonData)
	return nil
}

func ProcessJoinGroupResp(decoder *decoder.PacketDecoder, resp *common.Response) error {
	r, err := decoder.ExtractJoinGroupResp()
	if err != nil {
		return err
	}
	jsonData, err := r.ToJSON()
	if err != nil {
		return err
	}
	resp.Msg = string(jsonData)
	return nil
}

func ProcessSyncGroupReq(decoder *decoder.PacketDecoder, req *common.Request) error {
	r, err := decoder.ExtractSyncGroupReq()
	if err != nil {
		return err
	}
	jsonData, err := r.ToJSON()
	if err != nil {
		return err
	}
	req.Msg = string(jsonData)
	return nil
}

func ProcessSyncGroupResp(decoder *decoder.PacketDecoder, resp *common.Response) error {
	r, err := decoder.ExtractSyncGroupResp()
	if err != nil {
		return err
	}
	jsonData, err := r.ToJSON()
	if err != nil {
		return err
	}
	resp.Msg = string(jsonData)
	return nil
}

func ProcessMetadataReq(decoder *decoder.PacketDecoder, req *common.Request) error {
	r, err := decoder.ExtractMetadataReq()
	if err != nil {
		return err
	}
	jsonData, err := r.ToJSON()
	if err != nil {
		return err
	}
	req.Msg = string(jsonData)
	return nil
}

var _ protocol.ProtocolStreamParser = &KafkaStreamParser{}

type KafkaStreamParser struct {
	correlationIdMap map[int32]struct{}
	clientId         string
}

func NewKafkaStreamParser() *KafkaStreamParser {
	return &KafkaStreamParser{
		correlationIdMap: make(map[int32]struct{}),
	}
}

func (parser *KafkaStreamParser) GetCorrelationIdMap() map[int32]struct{} {
	return parser.correlationIdMap
}

func (parser *KafkaStreamParser) setClientId(clientId string) {
	parser.clientId = clientId
}

func (parser *KafkaStreamParser) getClientId() string {
	return parser.clientId
}
