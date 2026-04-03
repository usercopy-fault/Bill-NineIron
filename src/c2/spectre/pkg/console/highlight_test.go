package console_test

import (
	"os"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/sbu/spectre-c2/pkg/console"
)

// TestMain forces TrueColor profile so lipgloss renders ANSI codes even outside a TTY.
func TestMain(m *testing.M) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	os.Exit(m.Run())
}

func TestHighlightKnownCommand(t *testing.T) {
	result := console.Highlight([]rune("agents"))
	if result == "agents" {
		t.Error("known command should be colored, got plain text")
	}
	// Should contain the word "agents" somewhere.
	if len(result) < 6 {
		t.Errorf("highlight result too short: %q", result)
	}
}

func TestHighlightUnknownCommand(t *testing.T) {
	result := console.Highlight([]rune("blargh --flag arg"))
	// Unknown command should still return non-empty colored output.
	if result == "" {
		t.Error("highlight should not return empty string")
	}
}

func TestHighlightAtTarget(t *testing.T) {
	result := console.Highlight([]rune("exec @all uptime"))
	if len(result) == 0 {
		t.Error("highlight should colorize exec @all uptime")
	}
}

func TestHighlightEmpty(t *testing.T) {
	result := console.Highlight([]rune(""))
	if result != "" {
		t.Errorf("empty input should return empty string, got %q", result)
	}
}

func TestHighlightFlag(t *testing.T) {
	result := console.Highlight([]rune("exec @all --timeout 60"))
	if len(result) == 0 {
		t.Error("highlight result should not be empty")
	}
}

func TestHighlightTrailingSpace(t *testing.T) {
	result := console.Highlight([]rune("agents "))
	// Should preserve trailing space.
	if len(result) == 0 {
		t.Error("highlight result should not be empty")
	}
	// The trailing space should be present for tab-completion UX.
	if result[len(result)-1] != ' ' {
		t.Errorf("highlight should preserve trailing space, got %q", result)
	}
}

func TestParseTargetsAll(t *testing.T) {
	agents, tags := console.ParseTargets("@all")
	if len(agents) != 0 || len(tags) != 0 {
		t.Errorf("@all should return empty slices, got agents=%v tags=%v", agents, tags)
	}
}

func TestParseTargetsEmpty(t *testing.T) {
	agents, tags := console.ParseTargets("")
	if len(agents) != 0 || len(tags) != 0 {
		t.Errorf("empty should return empty slices, got agents=%v tags=%v", agents, tags)
	}
}

func TestParseTargetsTag(t *testing.T) {
	agents, tags := console.ParseTargets("@scanners")
	if len(agents) != 0 {
		t.Errorf("want 0 agents, got %v", agents)
	}
	if len(tags) != 1 || tags[0] != "scanners" {
		t.Errorf("want tags=[scanners], got %v", tags)
	}
}

func TestParseTargetsSpecific(t *testing.T) {
	agents, tags := console.ParseTargets("kali-01,kali-02")
	if len(agents) != 2 {
		t.Errorf("want 2 agents, got %v", agents)
	}
	if len(tags) != 0 {
		t.Errorf("want 0 tags, got %v", tags)
	}
}

func TestParseTargetsMixed(t *testing.T) {
	agents, tags := console.ParseTargets("kali-01,@scanners")
	if len(agents) != 1 || agents[0] != "kali-01" {
		t.Errorf("want agents=[kali-01], got %v", agents)
	}
	if len(tags) != 1 || tags[0] != "scanners" {
		t.Errorf("want tags=[scanners], got %v", tags)
	}
}
