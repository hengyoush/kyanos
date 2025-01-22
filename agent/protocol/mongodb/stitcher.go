package mongodb

import (
	"fmt"
	. "kyanos/agent/protocol"
	"sort"
)

func FlattenSections(mongoDBFrame *MongoDBFrame) {
	for i := range mongoDBFrame.Sections {
		section := mongoDBFrame.Sections[i]
		for doc := range section.Documents {
			mongoDBFrame.Frame_body += section.Documents[doc]
			mongoDBFrame.Frame_body += " "
		}
	}
	mongoDBFrame.Sections = nil
}

func FindMoreToComeResponses(resps map[StreamId]*ParsedMessageQueue, errorCount *int, respFrame *MongoDBFrame, latestRespTs *uint64) {
	// In a more to come frame, the response frame's responseTo will be the requestID of the prior response frame
	curRespFrame := respFrame
	for curRespFrame.MoreToCome {
		// Look for the queue of the next response
		nextRespDeque, nextRespExists := resps[StreamId(curRespFrame.RequestId)]
		if !nextRespExists {
			fmt.Printf("Did not find a response deque extending the prior more to come response. requestID: %d\n", curRespFrame.RequestId)
			(*errorCount)++
			return
		}

		// Find the next response frame with a timestamp greater than the current response frame's timestamp
		nextRespIndex := sort.Search(len(*nextRespDeque), func(i int) bool {
			return (*nextRespDeque)[i].TimestampNs() > *latestRespTs
		})
		if nextRespIndex == len((*nextRespDeque)) || (*nextRespDeque)[nextRespIndex].TimestampNs() < *latestRespTs {
			fmt.Printf("Did not find a response extending the prior more to come response. requestID: %d\n", curRespFrame.RequestId)
			(*errorCount)++
			return
		}

		// Insert the sections of the next response into the current more to come response
		nextResp := (*nextRespDeque)[nextRespIndex].(*MongoDBFrame)
		respFrame.Sections = append(respFrame.Sections, nextResp.Sections...)

		// Update the length of the current response frame
		respFrame.Length += nextResp.Length
		respFrame.FrameBase.IncrByteSize(nextResp.FrameBase.ByteSize())

		nextResp.Consumed = true
		*latestRespTs = nextResp.TimestampNs()
		curRespFrame = nextResp
	}
	// TODO(kpattaswamy): In the case of "missing" more to come middle/tail frames, determine whether
	// they are truly missing or have not been parsed yet.
}
