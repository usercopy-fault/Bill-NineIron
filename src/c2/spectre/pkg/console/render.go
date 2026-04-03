package console

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/sbu/spectre-c2/pkg/console/ui"
)

// TaskBlock renders a completed task result as a Warp-style output block.
func TaskBlock(out io.Writer, agentID, taskID, cmdLine string, exitCode int, output string, duration time.Duration) {
	status := ui.SuccessStyle.Render("✓ exit 0")
	if exitCode != 0 {
		status = ui.FailStyle.Render(fmt.Sprintf("✗ exit %d", exitCode))
	}

	shortTask := taskID
	if len(taskID) > 8 {
		shortTask = taskID[:8] + "…"
	}

	header := fmt.Sprintf("%s  %s  %s  %s",
		ui.HeaderStyle.Render(agentID),
		ui.DimStyle.Render(shortTask),
		ui.DimStyle.Render(duration.Round(time.Millisecond).String()),
		status,
	)
	body := strings.TrimRight(output, "\n")
	if body == "" {
		body = ui.DimStyle.Render("(no output)")
	}
	block := ui.BorderStyle.Render(header + "\n" + ui.DimStyle.Render("$ "+cmdLine) + "\n" + body)
	fmt.Fprintln(out, block)
}

// AgentRow holds display data for one agent row.
type AgentRow struct {
	Hostname    string
	ID          string
	TailscaleIP string
	Status      string
	Mode        string
	CPU         string
	Mem         string
	Tags        string
}

// AgentTable renders the agent list as a Lip Gloss table.
func AgentTable(out io.Writer, rows []AgentRow) {
	if len(rows) == 0 {
		fmt.Fprintln(out, ui.WarnStyle.Render("  No agents connected."))
		return
	}

	colW := []int{16, 10, 16, 12, 8, 6, 6, 20}
	hdr := rowLine([]string{"HOSTNAME", "ID", "TAILSCALE", "STATUS", "MODE", "CPU", "MEM", "TAGS"}, colW, ui.HeaderStyle)
	sep := ui.DimStyle.Render(strings.Repeat("─", sum(colW)+len(colW)*3))

	fmt.Fprintln(out, sep)
	fmt.Fprintln(out, hdr)
	fmt.Fprintln(out, sep)

	for _, r := range rows {
		statusStr := ui.SuccessStyle.Render("● " + r.Status)
		if r.Status != "online" {
			statusStr = ui.DimStyle.Render("○ " + r.Status)
		}
		fmt.Fprintln(out, rowLine([]string{
			r.Hostname, r.ID, r.TailscaleIP, statusStr, r.Mode, r.CPU, r.Mem, r.Tags,
		}, colW, lipgloss.NewStyle()))
	}
	fmt.Fprintln(out, sep)
	fmt.Fprintf(out, ui.DimStyle.Render("  %d agent(s)")+"\n", len(rows))
}

func rowLine(cells []string, widths []int, style lipgloss.Style) string {
	var sb strings.Builder
	for i, c := range cells {
		w := 10
		if i < len(widths) {
			w = widths[i]
		}
		// Strip ANSI for length calculation (approximate).
		plain := stripANSI(c)
		pad := w - len(plain)
		if pad < 0 {
			pad = 0
		}
		sb.WriteString("  ")
		sb.WriteString(style.Render(c))
		sb.WriteString(strings.Repeat(" ", pad))
	}
	return sb.String()
}

func sum(s []int) int {
	n := 0
	for _, v := range s {
		n += v
	}
	return n
}

// stripANSI removes ANSI escape sequences for length calculation.
func stripANSI(s string) string {
	var out strings.Builder
	inSeq := false
	for _, r := range s {
		if r == '\x1b' {
			inSeq = true
			continue
		}
		if inSeq {
			if r == 'm' {
				inSeq = false
			}
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

// FindingRow holds display data for one finding row.
type FindingRow struct {
	ID       string
	HostIP   string
	Port     int
	Severity string
	Title    string
	CVSS     float32
}

// FindingsTable renders findings with severity-colored rows.
func FindingsTable(out io.Writer, rows []FindingRow) {
	if len(rows) == 0 {
		fmt.Fprintln(out, ui.WarnStyle.Render("  No findings."))
		return
	}
	sep := ui.DimStyle.Render(strings.Repeat("─", 90))
	fmt.Fprintln(out, sep)
	fmt.Fprintln(out, ui.HeaderStyle.Render(fmt.Sprintf("  %-8s  %-16s  %-6s  %-10s  %-5s  %s", "ID", "HOST", "PORT", "SEVERITY", "CVSS", "TITLE")))
	fmt.Fprintln(out, sep)
	for _, f := range rows {
		sev := f.Severity
		st, ok := ui.SevStyles[sev]
		if !ok {
			st = ui.DimStyle
		}
		shortID := f.ID
		if len(f.ID) > 8 {
			shortID = f.ID[:8]
		}
		line := fmt.Sprintf("  %-8s  %-16s  %-6d  %-10s  %-5.1f  %s",
			shortID, f.HostIP, f.Port, st.Render(strings.ToUpper(sev)), f.CVSS, f.Title)
		fmt.Fprintln(out, line)
	}
	fmt.Fprintln(out, sep)
}
