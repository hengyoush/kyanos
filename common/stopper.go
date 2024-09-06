package common

import "time"

var faststoppers *[]chan int
var slowstoppers *[]chan int

func AddToFastStopper(c chan int) {
	*faststoppers = append(*faststoppers, c)
}

func AddToSlowStopper(c chan int) {
	*slowstoppers = append(*slowstoppers, c)
}

func SendStopSignal() {
	Log.Debugf("%d fast stoppers needs to be signal\n", len(*faststoppers))
	for _, s := range *faststoppers {
		s <- 1
	}
	time.Sleep(500 * time.Millisecond)
	Log.Debugf("%d slow stoppers needs to be signal\n", len(*slowstoppers))
	for _, s := range *slowstoppers {
		s <- 1
	}
}
