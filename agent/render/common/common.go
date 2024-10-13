package common

import (
	"kyanos/agent/analysis/common"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

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
