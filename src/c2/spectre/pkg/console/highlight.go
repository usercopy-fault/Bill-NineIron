package console

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/sbu/spectre-c2/pkg/console/ui"
)

// Highlight applies per-token ANSI colors to the input line.
// Passed to reeflective/readline as the SyntaxHighlighter callback.
// Command (green) | flag (grey) | @target (cyan) | arg (white) | unknown-cmd (red)
func Highlight(line []rune) string {
	input := string(line)
	if strings.TrimSpace(input) == "" {
		return input
	}
	tokens := strings.Fields(input)
	if len(tokens) == 0 {
		return input
	}

	out := make([]string, len(tokens))
	for i, tok := range tokens {
		switch {
		case i == 0:
			if ui.KnownCommands[strings.ToLower(tok)] {
				out[i] = ui.StyleCmd.Render(tok)
			} else {
				out[i] = ui.StyleError.Render(tok)
			}
		case strings.HasPrefix(tok, "--") || (strings.HasPrefix(tok, "-") && len(tok) == 2):
			out[i] = ui.StyleFlag.Render(tok)
		case strings.HasPrefix(tok, "@"):
			out[i] = ui.StyleTarget.Render(tok)
		case strings.HasPrefix(tok, "--session") || tok == "-s":
			out[i] = ui.StyleSession.Render(tok)
		default:
			out[i] = ui.StyleArg.Render(tok)
		}
	}
	// Re-join preserving original spacing.
	result := strings.Join(out, " ")
	// Preserve trailing space for tab-completion UX.
	if strings.HasSuffix(input, " ") {
		result += " "
	}
	return result
}

// ParseTargets re-exports ui.ParseTargets for callers that import pkg/console directly.
func ParseTargets(target string) (agents []string, tags []string) {
	return ui.ParseTargets(target)
}

// Exported style accessors for the commands package.
func WarnStyle() lipgloss.Style   { return ui.WarnStyle }
func DimStyle() lipgloss.Style    { return ui.DimStyle }
func HeaderStyle() lipgloss.Style { return ui.HeaderStyle }
