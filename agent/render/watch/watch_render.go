package watch

import (
	"cmp"
	"context"
	"fmt"
	"kyanos/agent/analysis/common"
	"kyanos/agent/protocol"
	rc "kyanos/agent/render/common"
	"kyanos/bpf"
	c "kyanos/common"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var lock *sync.Mutex = &sync.Mutex{}

type watchCol struct {
	name       string
	cmp        func(c1 *common.AnnotatedRecord, c2 *common.AnnotatedRecord, reverse bool) int
	data       func(c *common.AnnotatedRecord) string
	width      int
	metricType common.MetricType
}

var (
	cols       []watchCol
	sortKeyMap watchKeyMap
	idCol      watchCol = watchCol{
		name:  "id",
		cmp:   nil,
		width: 5,
	}
	connCol watchCol = watchCol{
		name: "Connection",
		cmp: func(c1, c2 *common.AnnotatedRecord, reverse bool) int {
			if reverse {
				return cmp.Compare(c2.ConnDesc.SimpleString(), c1.ConnDesc.SimpleString())
			} else {
				return cmp.Compare(c1.ConnDesc.SimpleString(), c2.ConnDesc.SimpleString())
			}
		},
		data:  func(c *common.AnnotatedRecord) string { return c.ConnDesc.SimpleString() },
		width: 40,
	}
	protoCol watchCol = watchCol{
		name: "Proto",
		cmp: func(c1, c2 *common.AnnotatedRecord, reverse bool) int {
			if reverse {
				return cmp.Compare(c2.Protocol, c1.Protocol)
			} else {
				return cmp.Compare(c1.Protocol, c2.Protocol)
			}
		},
		data: func(c *common.AnnotatedRecord) string {
			return bpf.ProtocolNamesMap[bpf.AgentTrafficProtocolT(c.ConnDesc.Protocol)]
		},
		width: 6,
	}
	totalTimeCol watchCol = watchCol{
		name: "TotalTime",
		cmp: func(c1, c2 *common.AnnotatedRecord, reverse bool) int {
			if reverse {
				return cmp.Compare(c2.TotalDuration, c1.TotalDuration)
			} else {
				return cmp.Compare(c1.TotalDuration, c2.TotalDuration)
			}
		},
		data: func(r *common.AnnotatedRecord) string {
			return fmt.Sprintf("%.2f", c.ConvertDurationToMillisecondsIfNeeded(r.TotalDuration, false))
		},
		width:      10,
		metricType: common.TotalDuration,
	}
	reqSizeCol watchCol = watchCol{
		name: "ReqSize",
		cmp: func(c1, c2 *common.AnnotatedRecord, reverse bool) int {
			if reverse {
				return cmp.Compare(c2.ReqSize, c1.ReqSize)
			} else {
				return cmp.Compare(c1.ReqSize, c2.ReqSize)
			}
		},
		data:       func(c *common.AnnotatedRecord) string { return fmt.Sprintf("%d", c.ReqSize) },
		width:      10,
		metricType: common.RequestSize,
	}
	respSizeCol watchCol = watchCol{
		name: "RespSize",
		cmp: func(c1, c2 *common.AnnotatedRecord, reverse bool) int {
			if reverse {
				return cmp.Compare(c2.RespSize, c1.RespSize)
			} else {
				return cmp.Compare(c1.RespSize, c2.RespSize)
			}
		},
		data:       func(c *common.AnnotatedRecord) string { return fmt.Sprintf("%d", c.RespSize) },
		width:      10,
		metricType: common.ResponseSize,
	}
	processCol watchCol = watchCol{
		name: "Process",
		cmp: func(c1, c2 *common.AnnotatedRecord, reverse bool) int {
			if reverse {
				return cmp.Compare(c2.Pid, c1.Pid)
			} else {
				return cmp.Compare(c1.Pid, c2.Pid)
			}
		},
		data:  func(r *common.AnnotatedRecord) string { return c.GetPidCmdString(int32(r.Pid)) },
		width: 15,
	}
	netInternalCol watchCol = watchCol{
		name: "Net/Internal",
		cmp: func(c1, c2 *common.AnnotatedRecord, reverse bool) int {
			if reverse {
				return cmp.Compare(c2.BlackBoxDuration, c1.BlackBoxDuration)
			} else {
				return cmp.Compare(c1.BlackBoxDuration, c2.BlackBoxDuration)
			}
		},
		data: func(r *common.AnnotatedRecord) string {
			return fmt.Sprintf("%.2f", c.ConvertDurationToMillisecondsIfNeeded(r.BlackBoxDuration, false))
		},
		width:      13,
		metricType: common.BlackBoxDuration,
	}
	readSocketCol watchCol = watchCol{
		name: "ReadSocketTime",
		cmp: func(c1, c2 *common.AnnotatedRecord, reverse bool) int {
			if reverse {
				return cmp.Compare(c2.ReadFromSocketBufferDuration, c1.ReadFromSocketBufferDuration)
			} else {
				return cmp.Compare(c1.ReadFromSocketBufferDuration, c2.ReadFromSocketBufferDuration)
			}
		},
		data: func(r *common.AnnotatedRecord) string {
			return fmt.Sprintf("%.2f", c.ConvertDurationToMillisecondsIfNeeded(r.ReadFromSocketBufferDuration, false))
		},
		width:      15,
		metricType: common.ReadFromSocketBufferDuration,
	}
)

type model struct {
	table                 table.Model
	viewport              viewport.Model
	spinner               spinner.Model
	help                  help.Model
	records               *[]*common.AnnotatedRecord
	chosen                bool
	ready                 bool
	wide                  bool
	staticRecord          bool
	initialWindownSizeMsg tea.WindowSizeMsg
	sortBy                rc.SortBy
	reverse               bool
	options               WatchOptions
}

func NewModel(options WatchOptions, records *[]*common.AnnotatedRecord, initialWindownSizeMsg tea.WindowSizeMsg,
	sortBy common.MetricType, reverse bool) tea.Model {
	var m tea.Model = &model{
		table:                 initTable(options),
		viewport:              viewport.New(100, 100),
		spinner:               spinner.New(spinner.WithSpinner(spinner.Dot)),
		help:                  help.New(),
		records:               records,
		chosen:                false,
		ready:                 false,
		wide:                  options.WideOutput,
		staticRecord:          options.StaticRecord,
		initialWindownSizeMsg: initialWindownSizeMsg,
		options:               options,
	}
	if sortBy != common.NoneType {
		for idx, col := range cols {
			if col.metricType == sortBy {
				m.(*model).sortBy = rc.SortBy(idx)
				m.(*model).reverse = !reverse
				m.(*model).updateTableSortBy(idx)
				break
			}
		}
	}
	return m
}

func initWatchCols(wide bool) {
	cols = make([]watchCol, 0)
	cols = []watchCol{idCol, connCol, protoCol, totalTimeCol, reqSizeCol, respSizeCol}
	if wide {
		cols = slices.Insert(cols, 1, processCol)
	}
	cols = append(cols, netInternalCol, readSocketCol)
}

func initDetailViewKeyMap(cols []watchCol) {
	sortKeyMap = watchKeyMap{}
	for idx, col := range cols {
		if idx == 0 {
			continue
		}
		idxStr := fmt.Sprintf("%d", idx)
		sortKeyMap[idxStr] = key.NewBinding(
			key.WithKeys(idxStr),
			key.WithHelp(idxStr, fmt.Sprintf("sort by %s", col.name)),
		)
	}
}

func initTable(options WatchOptions) table.Model {
	initWatchCols(options.WideOutput)
	initDetailViewKeyMap(cols)
	columns := []table.Column{}
	for _, eachCol := range cols {
		columns = append(columns, table.Column{
			Title: eachCol.name,
			Width: eachCol.width,
		})
	}
	t := table.New(
		table.WithColumns(columns),
		table.WithRows([]table.Row{}),
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
	if m.staticRecord {
		m.updateRowsInTable()
		m.updateDetailViewPortSize(m.initialWindownSizeMsg)
		return nil
	} else {
		return tea.Batch(m.spinner.Tick)
	}
}

func (m *model) sortConnstats(connstats *[]*common.AnnotatedRecord) {
	col := cols[m.sortBy]
	if m.sortBy > 0 && col.cmp != nil {
		slices.SortFunc(*connstats, func(c1, c2 *common.AnnotatedRecord) int {
			return col.cmp(c1, c2, m.reverse)
		})
	}
}
func (m *model) updateRowsInTable() {
	lock.Lock()
	defer lock.Unlock()
	rows := make([]table.Row, 0)
	if len(rows) < len(*m.records) {
		// records := (*m.records)[len(rows):]
		m.sortConnstats(m.records)
		records := (*m.records)
		idx := 1
		for i, record := range records {
			var row table.Row
			for colIdx := range m.table.Columns() {
				if colIdx == 0 {
					row = append(row, fmt.Sprintf("%d", i+idx))
				} else {
					row = append(row, cols[colIdx].data(record))
				}
			}

			rows = append(rows, row)
		}
		m.table.SetRows(rows)
	}
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case spinner.TickMsg, rc.TickMsg:
		m.updateRowsInTable()
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			if m.chosen {
				m.chosen = false
			} else {
				if m.staticRecord {
					return m, nil
				} else {
					return m, tea.Quit
				}
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		case "1", "2", "3", "4", "5", "6", "7", "8":
			i, err := strconv.Atoi(msg.String())
			if !m.chosen {
				if err == nil {
					m.updateTableSortBy(i)
				}
			}
		case "n", "p":
			if !m.chosen {
				break
			}
			if msg.String() == "n" {
				m.table.SetCursor(m.table.Cursor() + 1)
			} else {
				m.table.SetCursor(m.table.Cursor() - 1)
			}
			fallthrough
		case "enter":
			m.chosen = true

			if m.chosen {
				selected := m.table.SelectedRow()
				if selected != nil {
					idx, _ := strconv.Atoi(selected[0])
					r := (*m.records)[idx-1]
					line := strings.Repeat("+", m.viewport.Width)
					timeDetail := ViewRecordTimeDetailAsFlowChart(r)
					// m.viewport.SetContent("[Request]\n\n" + c.TruncateString(r.Req.FormatToString(), 1024) + "\n" + line + "\n[Response]\n\n" +
					// 	c.TruncateString(r.Resp.FormatToString(), 10240))
					m.viewport.SetContent(timeDetail + "\n" + line + "\n" +
						"[Request]\n\n" + c.TruncateString(r.Req.FormatToString(), m.options.MaxRecordContentDisplayBytes) + "\n" + line + "\n[Response]\n\n" +
						c.TruncateString(r.Resp.FormatToString(), m.options.MaxRecordContentDisplayBytes))
				} else {
					panic("!")
				}
			}
			return m, nil
			// return m, tea.Batch(
			// 	tea.Printf("Let's go to %s!", m.table.SelectedRow()[1]),
			// )
		}
	case tea.WindowSizeMsg:
		m.updateDetailViewPortSize(msg)
	}
	if m.chosen {
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	} else {
		m.table, cmd = m.table.Update(msg)
		if cmd == nil {
			cmd = rc.DoTick()
		}
		return m, cmd
	}
}

func (m *model) updateTableSortBy(newSortBy int) {
	if newSortBy > 0 && newSortBy < len(cols) {
		prevSortBy := m.sortBy
		m.sortBy = rc.SortBy(newSortBy)
		m.reverse = !m.reverse
		cols := m.table.Columns()
		if prevSortBy != 0 {
			col := &cols[prevSortBy]
			col.Title = strings.TrimRight(col.Title, "↑")
			col.Title = strings.TrimRight(col.Title, "↓")
		}
		col := &cols[m.sortBy]
		if m.reverse {
			col.Title = col.Title + "↓"
		} else {
			col.Title = col.Title + "↑"
		}
		m.table.SetColumns(cols)
		m.updateRowsInTable()
	}
}

func (m *model) updateDetailViewPortSize(msg tea.WindowSizeMsg) {
	headerHeight := lipgloss.Height(m.headerView())
	footerHeight := lipgloss.Height(m.footerView())
	verticalMarginHeight := headerHeight + footerHeight
	if !m.ready {
		// Since this program is using the full size of the viewport we
		// need to wait until we've received the window dimensions before
		// we can initialize the viewport. The initial dimensions come in
		// quickly, though asynchronously, which is why we wait for them
		// here.
		m.viewport = viewport.New(msg.Width, msg.Height-verticalMarginHeight)
		m.ready = true
	} else {
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - verticalMarginHeight
	}
}

func (m *model) View() string {
	if m.chosen {
		selected := m.table.SelectedRow()
		if selected != nil {
			if !m.ready {
				return "\n  Initializing..."
			}
			return fmt.Sprintf("%s\n%s\n%s", m.headerView(), m.viewport.View(), m.footerView())
		} else {
			return "failed"
		}
	} else {
		var s string
		if !m.staticRecord {
			s += fmt.Sprintf("\n %s Events received: %d\n\n", m.spinner.View(), len(m.table.Rows()))
		} else {
			s += fmt.Sprintf("\n Events Num: %d\n\n", len(m.table.Rows()))
		}
		return s + rc.BaseTableStyle.Render(m.table.View()) + "\n  " + m.table.HelpView() + "\n"
	}
}
func (m model) headerView() string {
	title := titleStyle.Render(fmt.Sprintf("Record Detail: %d (Total: %d)", m.table.Cursor()+1, len(m.table.Rows())))
	line := strings.Repeat("─", max(0, m.viewport.Width-lipgloss.Width(title)))
	return lipgloss.JoinHorizontal(lipgloss.Center, title, line)
}

func (m model) footerView() string {
	info := infoStyle.Render(fmt.Sprintf("%3.f%%", m.viewport.ScrollPercent()*100))
	line := strings.Repeat("─", max(0, m.viewport.Width-lipgloss.Width(info)))
	return lipgloss.JoinHorizontal(lipgloss.Center, line, info) + "\n" + m.help.View(detailViewKeyMap)
}

type watchKeyMap rc.KeyMap

var (
	titleStyle = func() lipgloss.Style {
		b := lipgloss.RoundedBorder()
		b.Right = "├"
		return lipgloss.NewStyle().BorderStyle(b).Padding(0, 1)
	}()

	infoStyle = func() lipgloss.Style {
		b := lipgloss.RoundedBorder()
		b.Left = "┤"
		return titleStyle.BorderStyle(b)
	}()

	detailViewKeyMap = watchKeyMap{
		"n": key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "next"),
		),
		"p": key.NewBinding(
			key.WithKeys("p"),
			key.WithHelp("p", "previous"),
		),
	}
)

func (k watchKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{detailViewKeyMap["n"], detailViewKeyMap["p"]}
}

func (k watchKeyMap) FullHelp() [][]key.Binding {
	result := [][]key.Binding{}
	result = append(result, []key.Binding{detailViewKeyMap["n"], detailViewKeyMap["p"]})
	sortkeys := []key.Binding{}
	for idx := range cols {
		if idx == 0 {
			continue
		}
		sortkeys = append(sortkeys, sortKeyMap[fmt.Sprintf("%d", idx)])
	}
	result = append(result, sortkeys)
	return result
}

func RunWatchRender(ctx context.Context, ch chan *common.AnnotatedRecord, options WatchOptions) {
	if options.DebugOutput {
		for {
			select {
			case <-ctx.Done():
				return
			case r := <-ch:
				c.BPFEventLog.Warnln(r.String(common.AnnotatedRecordToStringOptions{
					Nano: false,
					MetricTypeSet: common.MetricTypeSet{
						common.ResponseSize:                 false,
						common.RequestSize:                  false,
						common.ReadFromSocketBufferDuration: true,
						common.BlackBoxDuration:             true,
						common.TotalDuration:                true,
					}, IncludeSyscallStat: true,
					IncludeConnDesc: true,
					RecordToStringOptions: protocol.RecordToStringOptions{
						IncludeReqBody:     true,
						IncludeRespBody:    true,
						RecordMaxDumpBytes: 1024,
					},
				}))
			}
		}
	} else {
		records := &[]*common.AnnotatedRecord{}
		m := NewModel(options, records, tea.WindowSizeMsg{}, common.NoneType, false).(*model)
		if !options.StaticRecord {
			go func(mod *model, channel chan *common.AnnotatedRecord) {
				for {
					select {
					case <-ctx.Done():
						return
					case r := <-ch:
						lock.Lock()
						*m.records = append(*m.records, r)
						lock.Unlock()
					}
				}
			}(m, ch)
		}
		prog := tea.NewProgram(m, tea.WithContext(ctx), tea.WithAltScreen())
		if _, err := prog.Run(); err != nil {
			fmt.Println("Error running program:", err)
			os.Exit(1)
		}
	}

}

func (m *model) SortBy() rc.SortBy {
	return m.sortBy
}
