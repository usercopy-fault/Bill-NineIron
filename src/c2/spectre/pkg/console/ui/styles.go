// Package ui provides shared Lip Gloss styles and helpers for the SPECTRE-C2 operator console.
// It is kept as a leaf package (no imports from console or commands) so that both
// the console package and the commands package can import it without cycles.
package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	StyleCmd     = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)  // green bold
	StyleFlag    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))              // grey
	StyleTarget  = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true)  // cyan bold
	StyleArg     = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))             // white
	StyleError   = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)   // red bold
	StyleSession = lipgloss.NewStyle().Foreground(lipgloss.Color("13"))             // magenta

	BorderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("12")).
			Padding(0, 1)

	HeaderStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true)
	SuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	FailStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	WarnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	DimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Faint(true)

	SevStyles = map[string]lipgloss.Style{
		"critical": lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true),
		"high":     lipgloss.NewStyle().Foreground(lipgloss.Color("9")),
		"medium":   lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		"low":      lipgloss.NewStyle().Foreground(lipgloss.Color("12")),
		"info":     lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}

	KnownCommands = map[string]bool{
		"agents":   true,
		"exec":     true,
		"scan":     true,
		"recon":    true,
		"fuzz":     true,
		"exploit":  true,
		"report":   true,
		"sessions": true,
		"findings": true,
		"triage":   true,
		"analyze":  true,
		"db":       true,
		"use":      true,
		"back":     true,
		"help":     true,
		"exit":     true,
		"quit":     true,
		"upload":   true,
		"download": true,
		"shell":    true,
		"plugins":  true,
	}
)

// ParseTargets parses a target specifier into (agents, tags) slices.
//   - ""  or "@all"   -> nil, nil  (broadcast to all)
//   - "@scanners"     -> nil, ["scanners"]
//   - "kali-01,kali-02" -> ["kali-01","kali-02"], nil
func ParseTargets(target string) (agents []string, tags []string) {
	if target == "" || target == "@all" {
		return nil, nil
	}
	for _, t := range strings.Split(target, ",") {
		t = strings.TrimSpace(t)
		if strings.HasPrefix(t, "@") {
			tags = append(tags, strings.TrimPrefix(t, "@"))
		} else {
			agents = append(agents, t)
		}
	}
	return
}

