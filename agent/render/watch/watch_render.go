package watch

import (
	"context"
	"fmt"
	"kyanos/agent/analysis/common"
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

type WatchRender struct {
	model *model
}

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
}

func NewModel(options WatchOptions, records *[]*common.AnnotatedRecord, initialWindownSizeMsg tea.WindowSizeMsg) tea.Model {
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
	}
	return m
}

func initTable(options WatchOptions) table.Model {
	columns := []table.Column{
		{Title: "id", Width: 3},
		{Title: "Connection", Width: 40},
		{Title: "Proto", Width: 5},
		{Title: "TotalTime", Width: 10},
		{Title: "ReqSize", Width: 7},
		{Title: "RespSize", Width: 8},
	}
	if options.WideOutput {
		columns = slices.Insert(columns, 1, table.Column{
			Title: "Proc", Width: 20,
		})
		columns = append(columns, []table.Column{
			{Title: "Net/Internal", Width: 15},
			{Title: "ReadSocket", Width: 12},
		}...)
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
	if m.staticRecord {
		m.updateRowsInTable()
		m.updateDetailViewPortSize(m.initialWindownSizeMsg)
		return nil
	} else {
		return tea.Batch(m.spinner.Tick)
	}
}

func (m *model) updateRowsInTable() {
	rows := m.table.Rows()
	if len(rows) < len(*m.records) {
		records := (*m.records)[len(rows):]
		idx := len(rows) + 1
		for i, record := range records {
			var row table.Row
			if m.wide {
				row = table.Row{
					fmt.Sprintf("%d", i+idx),
					c.GetPidCmdString(int32(record.Pid)),
					record.ConnDesc.SimpleString(),
					bpf.ProtocolNamesMap[bpf.AgentTrafficProtocolT(record.ConnDesc.Protocol)],
					fmt.Sprintf("%.2f", c.ConvertDurationToMillisecondsIfNeeded(record.TotalDuration, false)),
					fmt.Sprintf("%d", record.ReqSize),
					fmt.Sprintf("%d", record.RespSize),
					fmt.Sprintf("%.2f", c.ConvertDurationToMillisecondsIfNeeded(record.BlackBoxDuration, false)),
					fmt.Sprintf("%.2f", c.ConvertDurationToMillisecondsIfNeeded(record.ReadFromSocketBufferDuration, false)),
				}
			} else {
				row = table.Row{
					fmt.Sprintf("%d", i+idx),
					record.ConnDesc.SimpleString(),
					bpf.ProtocolNamesMap[bpf.AgentTrafficProtocolT(record.ConnDesc.Protocol)],
					fmt.Sprintf("%.2f", c.ConvertDurationToMillisecondsIfNeeded(record.TotalDuration, false)),
					fmt.Sprintf("%d", record.ReqSize),
					fmt.Sprintf("%d", record.RespSize),
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
		lock.Lock()
		defer lock.Unlock()
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
					m.viewport.SetContent("[Request]\n\n" + c.TruncateString(r.Req.FormatToString(), 1024) + "\n" + line + "\n[Response]\n\n" +
						c.TruncateString(r.Resp.FormatToString(), 10240))
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
	return [][]key.Binding{{detailViewKeyMap["n"], detailViewKeyMap["p"]}}
}

func RunWatchRender(ctx context.Context, ch chan *common.AnnotatedRecord, options WatchOptions) {
	records := &[]*common.AnnotatedRecord{}
	m := NewModel(options, records, tea.WindowSizeMsg{}).(*model)
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
