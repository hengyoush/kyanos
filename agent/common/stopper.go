package common

// import (
// 	"kyanos/common"
// 	"time"
// )

// var faststoppers *[]chan int
// var slowstoppers *[]chan int

// func AddToFastStopper(c chan int) {
// 	*faststoppers = append(*faststoppers, c)
// }

// func AddToSlowStopper(c chan int) {
// 	*slowstoppers = append(*slowstoppers, c)
// }

// func SendStopSignal() {
// 	common.AgentLog.Debugf("%d fast stoppers needs to be signal\n", len(*faststoppers))
// 	for _, s := range *faststoppers {
// 		s <- 1
// 	}
// 	time.Sleep(500 * time.Millisecond)
// 	common.AgentLog.Debugf("%d slow stoppers needs to be signal\n", len(*slowstoppers))
// 	for _, s := range *slowstoppers {
// 		s <- 1
// 	}
// }

// func init() {
// 	_stoppers1 := make([]chan int, 0)
// 	faststoppers = &_stoppers1
// 	_stoppers2 := make([]chan int, 0)
// 	slowstoppers = &_stoppers2
// }
