package watch

import "strings"

type WatchOptions struct {
	wideOutput bool
	Opts       string
}

func (w *WatchOptions) Init() {
	if w.Opts != "" {
		if strings.Contains(w.Opts, "wide") {
			w.wideOutput = true
		}
	}
}
