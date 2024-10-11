package watch

import (
	"context"
	"fmt"
	"kyanos/agent/analysis/common"
	rc "kyanos/agent/render/common"
	"kyanos/bpf"
	c "kyanos/common"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var lock *sync.Mutex = &sync.Mutex{}

type TickMsg time.Time

func doTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

type WatchRender struct {
	model *model
}

type model struct {
	table    table.Model
	viewport viewport.Model
	records  *[]*common.AnnotatedRecord
	spinner  spinner.Model
	help     help.Model
	chosen   bool
	ready    bool
}

func (m model) Init() tea.Cmd { return tea.Batch(m.spinner.Tick) }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case spinner.TickMsg:
		rows := m.table.Rows()
		lock.Lock()
		defer lock.Unlock()
		if len(rows) < len(*m.records) {
			records := (*m.records)[len(rows):]
			idx := len(rows) + 1
			for i, record := range records {
				row := table.Row{
					fmt.Sprintf("%d", i+idx),
					record.ConnDesc.SimpleString(),
					bpf.ProtocolNamesMap[bpf.AgentTrafficProtocolT(record.ConnDesc.Protocol)],
					fmt.Sprintf("%.2f", c.ConvertDurationToMillisecondsIfNeeded(record.TotalDuration, false)),
					fmt.Sprintf("%d", record.ReqSize),
					fmt.Sprintf("%d", record.RespSize),
				}
				rows = append(rows, row)
			}
			m.table.SetRows(rows)
		}
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			if m.chosen {
				m.chosen = false
			} else {
				if m.table.Focused() {
					m.table.Blur()
				} else {
					m.table.Focus()
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
						c.TruncateString(r.Resp.FormatToString(), 10240) + "\n" + line)
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
			// m.viewport.YPosition = headerHeight
			// m.viewport.SetContent(m.content)
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - verticalMarginHeight
		}

	}
	if m.chosen {
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	} else {
		m.table, cmd = m.table.Update(msg)
		if cmd == nil {
			cmd = doTick()
		}
		return m, cmd
	}
}
func (m model) View() string {
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
		s := fmt.Sprintf("\n %s Events received: %d\n\n", m.spinner.View(), len(m.table.Rows()))
		return s + baseStyle.Render(m.table.View()) + "\n  " + m.table.HelpView() + "\n"
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

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

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

func RunWatchRender(ctx context.Context, ch chan *common.AnnotatedRecord) {
	columns := []table.Column{
		{Title: "id", Width: 3},
		{Title: "Connection", Width: 40},
		{Title: "Protocol", Width: 10},
		{Title: "Total Time", Width: 10},
		{Title: "Req Size", Width: 10},
		{Title: "Resp Size", Width: 10},
	}
	rows := []table.Row{}
	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(7),
		table.WithWidth(96),
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
	records := &[]*common.AnnotatedRecord{}
	m := model{t, viewport.New(100, 100), records, spinner.New(spinner.WithSpinner(spinner.Dot)), help.NewModel(), false, false}
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
	}(&m, ch)
	prog := tea.NewProgram(m, tea.WithContext(ctx), tea.WithAltScreen())
	if _, err := prog.Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
