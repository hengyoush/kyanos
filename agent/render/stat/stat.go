package stat

import (
	"context"
	"fmt"
	"kyanos/agent/analysis"
	"kyanos/agent/analysis/common"
	rc "kyanos/agent/render/common"
	"kyanos/agent/render/watch"
	"os"
	"sync"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var lock *sync.Mutex = &sync.Mutex{}

type model struct {
	statTable   table.Model
	sampleModel tea.Model
	spinner     spinner.Model

	connstats    *[]*analysis.ConnStat
	curConnstats *[]*analysis.ConnStat

	options common.AnalysisOptions

	chosenStat    bool
	chosenClassId string

	windownSizeMsg tea.WindowSizeMsg
}

func NewModel(options common.AnalysisOptions) tea.Model {
	return &model{
		statTable:   initTable(options),
		sampleModel: nil,
		spinner:     spinner.New(spinner.WithSpinner(spinner.Dot)),
		connstats:   nil,
		options:     options,
		chosenStat:  false,
	}
}

func initTable(options common.AnalysisOptions) table.Model {
	metric := options.EnabledMetricTypeSet.GetFirstEnabledMetricType()
	unit := rc.MetricTypeUnit[metric]
	columns := []table.Column{
		{Title: "id", Width: 3},
		{Title: "name", Width: 40},
		{Title: fmt.Sprintf("max(%s)", unit), Width: 10},
		{Title: fmt.Sprintf("avg(%s)", unit), Width: 10},
		{Title: fmt.Sprintf("p50(%s)", unit), Width: 10},
		{Title: fmt.Sprintf("p90(%s)", unit), Width: 10},
		{Title: fmt.Sprintf("p99(%s)", unit), Width: 10},
		{Title: "count", Width: 5},
	}
	if metric.IsTotalMeaningful() {
		columns = append(columns, table.Column{Title: fmt.Sprintf("total(%s)", unit), Width: 12})
	}
	rows := []table.Row{}
	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(7),
		// table.WithWidth(96),
	)
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)
	return t
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick)
}
func (m *model) updateStatTable(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case spinner.TickMsg:
		rows := make([]table.Row, 0)
		lock.Lock()
		defer lock.Unlock()
		if m.connstats != nil && m.curConnstats != m.connstats {
			m.curConnstats = m.connstats
			metric := m.options.EnabledMetricTypeSet.GetFirstEnabledMetricType()
			records := (*m.curConnstats)
			var row table.Row
			for i, record := range records {
				pCalc := record.PercentileCalculators[metric]
				p50, p90, p99 := pCalc.CalculatePercentile(0.5), pCalc.CalculatePercentile(0.9), pCalc.CalculatePercentile(0.99)
				row = table.Row{
					fmt.Sprintf("%d", i),
					record.ClassIdAsHumanReadable(record.ClassId),
					fmt.Sprintf("%.2f", record.MaxMap[metric]),
					fmt.Sprintf("%.2f", record.SumMap[metric]/float64(record.Count)),
					fmt.Sprintf("%.2f", p50),
					fmt.Sprintf("%.2f", p90),
					fmt.Sprintf("%.2f", p99),
					fmt.Sprintf("%d", record.Count),
				}
				if metric.IsTotalMeaningful() {
					row = append(row, fmt.Sprintf("%.1f", record.SumMap[metric]))
				}
				rows = append(rows, row)
			}
			m.statTable.SetRows(rows)
		}
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case tea.WindowSizeMsg:
		m.windownSizeMsg = msg
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "q", "ctrl+c":
			return m, tea.Quit
		case "enter":
			m.chosenStat = true
			// TODO 考虑sort
			cursor := m.statTable.Cursor()
			metric := m.options.EnabledMetricTypeSet.GetFirstEnabledMetricType()
			if m.curConnstats != nil {
				records := ((*m.curConnstats)[cursor].SamplesMap[metric])
				m.sampleModel = watch.NewModel(watch.WatchOptions{
					WideOutput:   true,
					StaticRecord: true,
				}, &records, m.windownSizeMsg)
			}

			return m, m.sampleModel.Init()
		}
	}
	m.statTable, cmd = m.statTable.Update(msg)
	return m, cmd
}

func (m *model) updateSampleTable(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.chosenStat = false
			return m, m.Init()
		case "esc":
			_, cmd = m.sampleModel.Update(msg)
			if cmd == nil {
				m.chosenStat = false
				return m, m.Init()
			}
		default:
			_, cmd = m.sampleModel.Update(msg)
		}
	}
	return m, cmd
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if !m.chosenStat {
		return m.updateStatTable(msg)
	} else {
		return m.updateSampleTable(msg)
	}
}

func (m *model) viewStatTable() string {
	totalCount := 0
	if m.curConnstats != nil {
		for _, each := range *m.curConnstats {
			totalCount += each.Count
		}
	}
	s := fmt.Sprintf("\n %s Events received: %d\n\n", m.spinner.View(), totalCount)

	return s + rc.BaseTableStyle.Render(m.statTable.View()) + "\n  " + m.statTable.HelpView() + "\n"
}

func (m *model) viewSampleTable() string {
	return m.sampleModel.View()
}

func (m *model) View() string {
	if !m.chosenStat {
		return m.viewStatTable()
	} else {
		return m.viewSampleTable()
	}
}
func StartStatRender(ctx context.Context, ch <-chan []*analysis.ConnStat, options common.AnalysisOptions) {
	m := NewModel(options).(*model)
	go func(mod *model, channel <-chan []*analysis.ConnStat) {
		for {
			select {
			case <-ctx.Done():
				return
			case r := <-ch:
				lock.Lock()
				m.connstats = &r
				lock.Unlock()
			}
		}
	}(m, ch)

	prog := tea.NewProgram(m, tea.WithContext(ctx), tea.WithAltScreen())
	if _, err := prog.Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
