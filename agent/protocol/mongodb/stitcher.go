package mongodb

import (
	"fmt"
	. "kyanos/agent/protocol"
	"sort"
)

func FlattenSections(mongoDBFrame *MongoDBFrame) {
	for i := range mongoDBFrame.sections {
		section := mongoDBFrame.sections[i]
		for doc := range section.documents {
			mongoDBFrame.frame_body += section.documents[doc]
			mongoDBFrame.frame_body += " "
		}
	}
	mongoDBFrame.sections = nil //注意这里清空怎么操作
}

func FindMoreToComeResponses(resps map[StreamId]*ParsedMessageQueue, errorCount *int, respFrame *MongoDBFrame, latestRespTs *uint64) {
	// 在一个更多消息的框架中，响应框架的 responseTo 将是先前响应框架的 requestID
	curRespFrame := respFrame
	for curRespFrame.moreToCome {
		// 查找下一个响应的队列
		nextRespDeque, nextRespExists := resps[StreamId(curRespFrame.requestId)]
		if !nextRespExists {
			fmt.Printf("Did not find a response deque extending the prior more to come response. requestID: %d\n", curRespFrame.requestId)
			(*errorCount)++
			return
		}

		// 查找时间戳大于当前响应框架时间戳的下一个响应框架
		nextRespIndex := sort.Search(len(*nextRespDeque), func(i int) bool {
			return (*nextRespDeque)[i].TimestampNs() > *latestRespTs
		})
		if nextRespIndex == len((*nextRespDeque)) || (*nextRespDeque)[nextRespIndex].TimestampNs() < *latestRespTs {
			fmt.Printf("Did not find a response extending the prior more to come response. requestID: %d\n", curRespFrame.requestId)
			(*errorCount)++
			return
		}

		// 插入下一个响应的部分数据到当前更多到来的响应的头部
		nextResp := (*nextRespDeque)[nextRespIndex].(*MongoDBFrame)
		curRespFrame.sections = append(curRespFrame.sections, nextResp.sections...)

		nextResp.consumed = true
		*latestRespTs = nextResp.TimestampNs()
		curRespFrame = nextResp
	}
	// TODO(kpattaswamy): In the case of "missing" more to come middle/tail frames, determine whether
	// they are truly missing or have not been parsed yet.
}
