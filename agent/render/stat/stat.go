package stat

import (
	"cmp"
	"context"
	"fmt"
	"kyanos/agent/analysis"
	"kyanos/agent/analysis/common"
	rc "kyanos/agent/render/common"
	"kyanos/agent/render/watch"
	"kyanos/bpf"
	c "kyanos/common"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var lock *sync.Mutex = &sync.Mutex{}

type statTableKeyMap rc.KeyMap

var sortByKeyMap = statTableKeyMap{
	"1": key.NewBinding(
		key.WithKeys("1"),
		key.WithHelp("1", "sort by name"),
	),
	"2": key.NewBinding(
		key.WithKeys("2"),
		key.WithHelp("2", "sort by max"),
	),
	"3": key.NewBinding(
		key.WithKeys("3"),
		key.WithHelp("3", "sort by avg"),
	),
	"4": key.NewBinding(
		key.WithKeys("4"),
		key.WithHelp("4", "sort by p50"),
	),
	"5": key.NewBinding(
		key.WithKeys("5"),
		key.WithHelp("5", "sort by p90"),
	),
	"6": key.NewBinding(
		key.WithKeys("6"),
		key.WithHelp("6", "sort by p99"),
	),
	"7": key.NewBinding(
		key.WithKeys("7"),
		key.WithHelp("7", "sort by count"),
	),
	"8": key.NewBinding(
		key.WithKeys("8"),
		key.WithHelp("8", "sort by total"),
	),
}

func (k statTableKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{sortByKeyMap["1"], sortByKeyMap["2"],
		sortByKeyMap["3"], sortByKeyMap["4"],
		sortByKeyMap["5"], sortByKeyMap["6"],
		sortByKeyMap["7"], sortByKeyMap["8"],
	}
}

func (k statTableKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{sortByKeyMap["1"], sortByKeyMap["2"],
		sortByKeyMap["3"], sortByKeyMap["4"],
		sortByKeyMap["5"], sortByKeyMap["6"],
		sortByKeyMap["7"], sortByKeyMap["8"],
	}}
}

const (
	none rc.SortBy = iota
	name
	protocol // only valid when in overview mode
	max
	avg
	p50
	p90
	p99
	count
	total
	end
)

type model struct {
	statTable    table.Model
	subStatTable table.Model
	sampleModel  tea.Model
	spinner      spinner.Model
	additionHelp help.Model

	connstats       *[]*analysis.ConnStat // receive from upstream, don't modify it
	curConnstats    *[]*analysis.ConnStat // after sort&filter, used to display
	curSubConnstats *[]*analysis.ConnStat // after sort&filter, used to display
	resultChannel   <-chan []*analysis.ConnStat
	startTimeMills  int64

	options common.AnalysisOptions

	enableSubGroup bool
	chosenSub      bool
	curClassId     common.ClassId
	chosenStat     bool

	windownSizeMsg tea.WindowSizeMsg

	sortBy  rc.SortBy
	reverse bool
}

func NewModel(options common.AnalysisOptions) tea.Model {
	return &model{
		statTable:      initTable(options, false),
		subStatTable:   initTable(options, true),
		sampleModel:    nil,
		spinner:        spinner.New(spinner.WithSpinner(spinner.Dot)),
		startTimeMills: time.Now().UnixMilli(),
		additionHelp:   help.New(),
		connstats:      nil,
		options:        options,
		chosenStat:     false,
		chosenSub:      false,
		enableSubGroup: options.SubClassfierType != common.None,
	}
}

func initTable(options common.AnalysisOptions, isSub bool) table.Model {
	metric := options.EnabledMetricTypeSet.GetFirstEnabledMetricType()
	unit := rc.MetricTypeUnit[metric]
	columns := []table.Column{
		{Title: "id", Width: 3},
		{Title: common.ClassfierTypeNames[options.ClassfierType], Width: 40},
		{Title: fmt.Sprintf("max(%s)", unit), Width: 10},
		{Title: fmt.Sprintf("avg(%s)", unit), Width: 10},
		{Title: fmt.Sprintf("p50(%s)", unit), Width: 10},
		{Title: fmt.Sprintf("p90(%s)", unit), Width: 10},
		{Title: fmt.Sprintf("p99(%s)", unit), Width: 10},
		{Title: "count", Width: 10},
	}
	if options.Overview {
		columns = slices.Insert(columns, 2, table.Column{Title: "Protocol", Width: 10})
	}
	if isSub {
		columns[1] = table.Column{Title: common.ClassfierTypeNames[options.SubClassfierType], Width: 40}
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
func (m *model) updateConnStats() {
	var topStats, subStats []*analysis.ConnStat
	for _, each := range *m.connstats {
		if each.IsSub && m.curClassId != "" {
			if strings.HasPrefix(string(each.ClassId), string(m.curClassId)+"||") {
				subStats = append(subStats, each)
			}
		} else if !each.IsSub {
			topStats = append(topStats, each)
		}
	}
	m.sortConnstats(&topStats)
	m.sortConnstats(&subStats)
	m.curConnstats = &topStats
	m.curSubConnstats = &subStats
}
func renderToTable(connstats *[]*analysis.ConnStat, t *table.Model, metric common.MetricType, isSub bool, overview bool) {
	records := (*connstats)
	var row table.Row
	rows := make([]table.Row, 0)
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
		if overview {
			var protocol string
			if records, ok := record.SamplesMap[metric]; ok && len(records) > 0 {
				protocol = bpf.ProtocolNamesMap[bpf.AgentTrafficProtocolT(records[0].Protocol)]
			} else {
				protocol = "unknown"
			}
			row = slices.Insert(row, 2, protocol)
		}
		rows = append(rows, row)
	}
	t.SetRows(rows)
}
func (m *model) updateRowsInTable() {
	lock.Lock()
	defer lock.Unlock()
	if m.connstats != nil {
		m.updateConnStats()
		metric := m.options.EnabledMetricTypeSet.GetFirstEnabledMetricType()
		renderToTable(m.curConnstats, &m.statTable, metric, false, m.options.Overview)
		if m.enableSubGroup {
			renderToTable(m.curSubConnstats, &m.subStatTable, metric, true, m.options.Overview)
		}
	}
}
func connstatPercentileSortFunc(c1, c2 *analysis.ConnStat, line float64, m common.MetricType, reverse bool) int {
	pCalc1 := c1.PercentileCalculators[m]
	value1 := pCalc1.CalculatePercentile(line)
	pCalc2 := c2.PercentileCalculators[m]
	value2 := pCalc2.CalculatePercentile(line)
	if reverse {
		return cmp.Compare(value2, value1)
	} else {
		return cmp.Compare(value1, value2)

	}
}
func (m *model) sortConnstats(connstats *[]*analysis.ConnStat) {
	metric := m.options.EnabledMetricTypeSet.GetFirstEnabledMetricType()
	var sortBy rc.SortBy
	if !m.options.Overview && m.sortBy >= 2 {
		sortBy = m.sortBy + 1
	} else {
		sortBy = m.sortBy
	}
	switch sortBy {
	case max:
		slices.SortFunc(*connstats, func(c1, c2 *analysis.ConnStat) int {
			if m.reverse {
				return cmp.Compare(c2.MaxMap[metric], c1.MaxMap[metric])
			} else {
				return cmp.Compare(c1.MaxMap[metric], c2.MaxMap[metric])
			}
		})
	case protocol:
		slices.SortFunc(*connstats, func(c1, c2 *analysis.ConnStat) int {
			if m.reverse {
				return cmp.Compare(c2.SamplesMap[metric][0].Protocol, c1.SamplesMap[metric][0].Protocol)
			} else {
				return cmp.Compare(c1.SamplesMap[metric][0].Protocol, c2.SamplesMap[metric][0].Protocol)
			}
		})
	case avg:
		slices.SortFunc(*connstats, func(c1, c2 *analysis.ConnStat) int {
			if m.reverse {
				return cmp.Compare(c2.SumMap[metric]/float64(c2.Count), c1.SumMap[metric]/float64(c1.Count))
			} else {
				return cmp.Compare(c1.SumMap[metric]/float64(c1.Count), c2.SumMap[metric]/float64(c2.Count))
			}
		})
	case p50:
		slices.SortFunc(*connstats, func(c1, c2 *analysis.ConnStat) int {
			return connstatPercentileSortFunc(c1, c2, 0.5, metric, m.reverse)
		})
	case p90:
		slices.SortFunc(*connstats, func(c1, c2 *analysis.ConnStat) int {
			return connstatPercentileSortFunc(c1, c2, 0.9, metric, m.reverse)
		})
	case p99:
		slices.SortFunc(*connstats, func(c1, c2 *analysis.ConnStat) int {
			return connstatPercentileSortFunc(c1, c2, 0.99, metric, m.reverse)
		})
	case count:
		slices.SortFunc(*connstats, func(c1, c2 *analysis.ConnStat) int {
			if m.reverse {
				return cmp.Compare(c2.Count, c1.Count)
			} else {
				return cmp.Compare(c1.Count, c2.Count)
			}
		})
	case total:
		slices.SortFunc(*connstats, func(c1, c2 *analysis.ConnStat) int {
			if m.reverse {
				return cmp.Compare(c2.SumMap[metric], c1.SumMap[metric])
			} else {
				return cmp.Compare(c1.SumMap[metric], c2.SumMap[metric])
			}
		})
	case name:
		fallthrough
	default:
		slices.SortFunc(*connstats, func(c1, c2 *analysis.ConnStat) int {
			if m.reverse {
				return cmp.Compare(c2.ClassId, c1.ClassId)
			} else {
				return cmp.Compare(c1.ClassId, c2.ClassId)
			}
		})
	}
}
func (m *model) timeLimitReached() bool {
	return time.Now().UnixMilli()-m.startTimeMills > int64(m.options.TimeLimit*1000)
}
func (m *model) getAnalysisResult() (noresult bool) {
	m.options.HavestSignal <- struct{}{}
	connstats := <-m.resultChannel
	if connstats != nil {
		m.connstats = &connstats
	} else {
		lock.Lock()
		lock.Unlock()
	}
	if m.connstats != nil {
		m.updateRowsInTable()
		return false
	} else {
		return true
	}
}
func (m *model) updateStatTable(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case spinner.TickMsg, rc.TickMsg:
		if m.options.EnableBatchModel() && m.timeLimitReached() && len(m.statTable.Rows()) == 0 {
			m.getAnalysisResult()
		} else {
			m.updateRowsInTable()
		}
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case tea.WindowSizeMsg:
		m.windownSizeMsg = msg
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			if m.options.EnableBatchModel() && !m.timeLimitReached() {
				if len(m.statTable.Rows()) == 0 {
					if m.getAnalysisResult() {
						return m, tea.Quit
					}
					break
				}
			}
			fallthrough
		case "esc", "q":
			if m.chosenSub {
				m.chosenSub = false
				m.curClassId = ""
				return m, nil
			} else {
				return m, tea.Quit
			}
		case "1", "2", "3", "4", "5", "6", "7", "8":
			i, err := strconv.Atoi(strings.TrimPrefix(msg.String(), "ctrl+"))
			curTable := m.curTable()
			if err == nil && (i >= int(none) && i < int(end)) &&
				(i >= 0 && i < len(curTable.Columns())) {
				prevSortBy := m.sortBy

				m.sortBy = rc.SortBy(i)

				m.reverse = !m.reverse
				cols := curTable.Columns()
				if prevSortBy != none {
					col := &cols[prevSortBy]
					col.Title = strings.TrimRight(col.Title, "↑")
					col.Title = strings.TrimRight(col.Title, "↓")
				}
				col := &cols[i]
				if m.reverse {
					col.Title = col.Title + "↓"
				} else {
					col.Title = col.Title + "↑"
				}
				curTable.SetColumns(cols)
				m.updateRowsInTable()
			}
		case "enter":
			cursor := m.curTable().Cursor()
			if m.enableSubGroup && !m.chosenSub {
				// select sub
				curConnStat := (*m.curConnstats)[cursor]
				m.curClassId = curConnStat.ClassId
				m.chosenSub = true

				// update sub table col name
				cols := m.subStatTable.Columns()
				metric := m.options.EnabledMetricTypeSet.GetFirstEnabledMetricType()
				cType := analysis.GetClassfierType(m.options.SubClassfierType, m.options, curConnStat.SamplesMap[metric][0])
				cols[1].Title = common.ClassfierTypeNames[cType]
				m.subStatTable.SetColumns(cols)
			} else {
				m.chosenStat = true
				metric := m.options.EnabledMetricTypeSet.GetFirstEnabledMetricType()
				var records []*common.AnnotatedRecord
				if m.enableSubGroup && m.chosenSub {
					if m.curSubConnstats != nil {
						records = ((*m.curSubConnstats)[cursor].SamplesMap[metric])
					}
				} else {
					if m.curConnstats != nil {
						records = ((*m.curConnstats)[cursor].SamplesMap[metric])
					}
				}
				watchOpts := watch.WatchOptions{
					WideOutput:   true,
					StaticRecord: true,
				}
				watchOpts.Init()
				m.sampleModel = watch.NewModel(watchOpts, &records, m.windownSizeMsg, metric, true)

				return m, m.sampleModel.Init()
			}
		}
	}
	*m.curTable(), cmd = m.curTable().Update(msg)
	return m, cmd
}

func (m *model) curTable() *table.Model {
	if m.enableSubGroup && m.chosenSub {
		return &m.subStatTable
	} else {
		return &m.statTable
	}
}
func (m *model) curConnstatsSlice() *[]*analysis.ConnStat {
	if m.enableSubGroup && m.chosenSub {
		return m.curSubConnstats
	} else {
		return m.curConnstats
	}
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
	curConnstats := m.curConnstatsSlice()
	curTable := m.curTable()
	totalCount := 0
	if curConnstats != nil {
		for _, each := range *curConnstats {
			totalCount += each.Count
		}
	}
	var s string

	// s = fmt.Sprintf("\n %s Events received: %d\n\n", m.spinner.View(), totalCount)
	// s += rc.BaseTableStyle.Render(m.statTable.View()) + "\n  " + m.statTable.HelpView() + "\n" + m.additionHelp.View(sortByKeyMap)
	if m.options.EnableBatchModel() {

		var titleStyle = lipgloss.NewStyle().
			MarginLeft(1).
			MarginRight(5).
			Padding(0, 1).
			Italic(true).
			Bold(false).
			Foreground(lipgloss.Color("#FFF7DB")).Background(lipgloss.Color(rc.ColorGrid(1, 5)[2][0]))

		if m.options.EnableBatchModel() && m.timeLimitReached() || (m.connstats != nil && len(*m.connstats) > 0) {
			s += fmt.Sprintf("\n %s \n\n", titleStyle.Render(" Colleted events are here! "))
			s += rc.BaseTableStyle.Render(curTable.View()) + "\n  " + curTable.HelpView() + "\n\n  " + m.additionHelp.View(sortByKeyMap)
		} else {
			s += fmt.Sprintf("\n %s Collected %d events, %d seconds left\n\n %s\n\n", m.spinner.View(), m.options.CurrentReceivedSamples(),
				int64(m.options.TimeLimit)-((time.Now().UnixMilli()-m.startTimeMills)/1000),
				titleStyle.Render("Press `Ctrl+C` to display collected events"))
		}
	} else {
		s = fmt.Sprintf("\n %s Events received: %d\n\n", m.spinner.View(), totalCount)
		s += rc.BaseTableStyle.Render(curTable.View()) + "\n  " + curTable.HelpView() + "\n\n  " + m.additionHelp.View(sortByKeyMap)
	}
	return s
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
	c.SetLogToFile()
	m := NewModel(options).(*model)

	prog := tea.NewProgram(m, tea.WithContext(ctx), tea.WithAltScreen())

	go func(mod *model, channel <-chan []*analysis.ConnStat) {
		for {
			select {
			case <-ctx.Done():
				return
			case r := <-ch:
				if r != nil {
					lock.Lock()
					m.connstats = &r
					lock.Unlock()
					prog.Send(rc.TickMsg{})
					if options.EnableBatchModel() {
						return
					}
				}
			}
		}
	}(m, ch)
	m.resultChannel = ch
	m.sortBy = avg
	m.reverse = true

	if _, err := prog.Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}

func (m *model) SortBy() rc.SortBy {
	return m.sortBy
}
