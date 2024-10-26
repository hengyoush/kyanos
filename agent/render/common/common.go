package common

import (
	"kyanos/agent/analysis/common"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/lucasb-eyer/go-colorful"
)

const MaxColWidth = 70

type KeyMap map[string]key.Binding

type TickMsg time.Time

func DoTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

var BaseTableStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

var MetricTypeNames = map[common.MetricType]string{
	common.ResponseSize:                 "Response Size",
	common.RequestSize:                  "Request Size",
	common.TotalDuration:                "Total Duration",
	common.BlackBoxDuration:             "BlackBox Duration",
	common.ReadFromSocketBufferDuration: "Socket Read Time",
}

var MetricTypeSampleNames = map[common.MetricType]string{
	common.ResponseSize:                 "Max Response Size Samples",
	common.RequestSize:                  "Max Request Size Samples",
	common.TotalDuration:                "Max Total Duration",
	common.BlackBoxDuration:             "Max BlackBox Duration",
	common.ReadFromSocketBufferDuration: "Max Socket Read Time",
}

var MetricTypeUnit = map[common.MetricType]string{
	common.ResponseSize:                 "bytes",
	common.RequestSize:                  "bytes",
	common.TotalDuration:                "ms",
	common.BlackBoxDuration:             "ms",
	common.ReadFromSocketBufferDuration: "ms",
}

func ColorGrid(xSteps, ySteps int) [][]string {
	x0y0, _ := colorful.Hex("#F25D94")
	x1y0, _ := colorful.Hex("#EDFF82")
	x0y1, _ := colorful.Hex("#643AFF")
	x1y1, _ := colorful.Hex("#14F9D5")

	x0 := make([]colorful.Color, ySteps)
	for i := range x0 {
		x0[i] = x0y0.BlendLuv(x0y1, float64(i)/float64(ySteps))
	}

	x1 := make([]colorful.Color, ySteps)
	for i := range x1 {
		x1[i] = x1y0.BlendLuv(x1y1, float64(i)/float64(ySteps))
	}

	grid := make([][]string, ySteps)
	for x := 0; x < ySteps; x++ {
		y0 := x0[x]
		grid[x] = make([]string, xSteps)
		for y := 0; y < xSteps; y++ {
			grid[x][y] = y0.BlendLuv(x1[x], float64(y)/float64(xSteps)).Hex()
		}
	}

	return grid
}

type SortBy int8

type SortOption struct {
	sortBy  SortBy
	reverse bool
}
