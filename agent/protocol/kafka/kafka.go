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
		}

		return i
	}

	return -1
}

// ParseStream implements protocol.ProtocolStreamParser.
func (k *KafkaStreamParser) ParseStream(streamBuffer *buffer.StreamBuffer, messageType protocol.MessageType) protocol.ParseResult {
	buf := streamBuffer.Head().Buffer()
	var minPacketLength int32
	if messageType == protocol.Request {
		minPacketLength = common.KMinReqPacketLength
	} else {
		minPacketLength = common.KMinRespPacketLength
	}
	if len(buf) < int(minPacketLength) {
		return protocol.ParseResult{
			ParseState: protocol.NeedsMoreData,
		}
	}
	binaryDecoder := protocol.NewBinaryDecoder(buf)
	payloadLength, err := protocol.ExtractBEInt[int32](binaryDecoder)
	if err != nil {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	if payloadLength+common.KMessageLengthBytes <= minPacketLength {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	var requestApiKey common.APIKey
	var requestApiVersion int16
	if messageType == protocol.Request {
		requestApiKeyInt, err := protocol.ExtractBEInt[int16](binaryDecoder)
		if err != nil || common.IsValidAPIKey(requestApiKeyInt) {
			return protocol.ParseResult{
				ParseState: protocol.Invalid,
			}
		}
		requestApiKey = common.APIKey(requestApiKeyInt)
		requestApiVersion, err = protocol.ExtractBEInt[int16](binaryDecoder)
		if !common.IsSupportedAPIVersion(requestApiKey, requestApiVersion) {
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

	if len(buf)-int(common.KMessageLengthBytes) < int(payloadLength) {
		return protocol.ParseResult{
			ParseState: protocol.NeedsMoreData,
		}
	}
	if messageType == protocol.Request {
		k.correlationIdMap[correlationId] = struct{}{}
	}
	msg := buf[common.KMessageLengthBytes : common.KMessageLengthBytes+payloadLength]
	fb, ok := protocol.CreateFrameBase(streamBuffer, int(common.KMessageLengthBytes+payloadLength))
	if !ok {
		return protocol.ParseResult{
			ParseState: protocol.Invalid,
		}
	}
	parseResult := common.Packet{
		FrameBase:     fb,
		CorrelationId: correlationId,
		Msg:           string(msg),
	}
	parseResult.SetIsReq(messageType == protocol.Request)
	return protocol.ParseResult{
		ParseState:     protocol.Success,
		ParsedMessages: []protocol.ParsedMessage{&parseResult},
		ReadBytes:      int(common.KMessageLengthBytes + payloadLength),
	}
}

// Match implements protocol.ProtocolStreamParser.
func (k *KafkaStreamParser) Match(reqStreams map[protocol.StreamId]*protocol.ParsedMessageQueue, respStreams map[protocol.StreamId]*protocol.ParsedMessageQueue) []protocol.Record {
	records := make([]protocol.Record, 0)
	errorCnt := 0
	reqStream, ok1 := reqStreams[0]
	respStream, ok2 := respStreams[0]
	if !ok1 || !ok2 {
		return records
	}
	correlationIdMap := make(map[int32]*common.Packet)
	for _, respMsg := range *respStream {
		correlationIdMap[respMsg.(*common.Packet).CorrelationId] = respMsg.(*common.Packet)
	}

	for _, reqMsg := range *reqStream {
		req := reqMsg.(*common.Packet)
		resp, ok := correlationIdMap[req.CorrelationId]
		if ok {
			r, err := processReqRespPair(req, resp)
			if err == nil {
				records = append(records, *r)
			} else {
				errorCnt++
			}
			req.Consumed = true
			delete(correlationIdMap, req.CorrelationId)
			delete(k.correlationIdMap, req.CorrelationId)
		}
	}

	// Resp packets left in the map don't have a matched request.
	for _, resp := range correlationIdMap {
		kc.ProtocolParserLog.Debugf("Response packet without a matching request: %v", resp.CorrelationId)
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
	*respStream = (*respStream)[:]
	return records
}

func ProcessReq(reqPacket *common.Packet) (*common.Request, error) {
	req := &common.Request{}
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
		return nil, err
	}
	respMsg, err := ProcessResp(resp, reqMsg.Apikey, reqMsg.ApiVersion)
	if err != nil {
		return nil, err
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
}
