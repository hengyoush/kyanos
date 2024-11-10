package loader

import (
	"context"
	"fmt"
	"kyanos/agent/common"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	spinnerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("63"))
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Margin(1, 0)
	dotStyle      = helpStyle.UnsetMargins()
	durationStyle = dotStyle
	appStyle      = lipgloss.NewStyle().Margin(1, 2, 0, 2)
)

type resultMsg struct {
	duration time.Duration
	ts       int64
	msg      string
}

func (r resultMsg) String() string {
	if r.duration == 0 {
		return dotStyle.Render(strings.Repeat(".", 30))
	}
	return fmt.Sprintf("%s %s", r.msg,
		durationStyle.Render(r.duration.String()))
}

type model struct {
	spinner  spinner.Model
	results  []resultMsg
	ch       chan string
	quitting bool
	killed   bool
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			m.killed = true
			return m, tea.Quit
		default:
			return m, nil
		}
	case resultMsg:
		if msg.msg == "quit" {
			m.quitting = true
			return m, tea.Quit
		}

		var duration time.Duration
		if len(m.results) != 0 && m.results[len(m.results)-1].ts > 0 {
			duration = time.Duration(int64(time.Now().UnixNano()) - m.results[len(m.results)-1].ts)
		} else {
			duration = 1
		}
		msg.duration = duration
		m.results = append(m.results[1:], msg)
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	default:
		return m, nil
	}
}

func (m model) View() string {
	var s string
	if m.quitting {
		s += "Kyanos exited."
	} else {
		s += m.spinner.View() + "🦜 Kyanos Loading..."
	}

	s += "\n\n"

	for _, res := range m.results {
		s += res.String() + "\n"
	}

	if !m.quitting {
		s += helpStyle.Render("Press ctrl+c to exit")
	}

	if m.quitting {
		s += "\n"
	}

	return appStyle.Render(s)
}

func Start(ctx context.Context, options common.AgentOptions) {
	const numLastResults = 5
	m := model{
		spinner: spinner.New(spinner.WithSpinner(spinner.Dot)),
		results: make([]resultMsg, numLastResults),
		ch:      options.LoadPorgressChannel,
	}

	p := tea.NewProgram(m, tea.WithContext(ctx))
	go func(m *model, ch chan string) {
		for {
			select {
			case <-ctx.Done():
				return
			case r := <-ch:
				p.Send(resultMsg{
					msg: r,
					ts:  time.Now().UnixNano(),
				})
			}
		}
	}(&m, options.LoadPorgressChannel)

	if _, err := p.Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
	if m.killed {
		os.Exit(0)
	}
}
