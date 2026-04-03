package server

import (
	"context"
	"os"
	"testing"

	"github.com/sbu/spectre-c2/pkg/db"
	pb "github.com/sbu/spectre-c2/pkg/proto"
)

func testDefender(t *testing.T) *Defender {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "defender-test-*.db")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	f.Close()

	store, err := db.Open(f.Name())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return NewDefender(store)
}

func TestDefenderBlocksRmRf(t *testing.T) {
	d := testDefender(t)

	resp := d.Validate(context.Background(), &pb.ValidateCommandRequest{
		OperatorId: "op-test",
		Args:       []string{"rm", "-rf", "/"},
	})

	if resp.Allowed {
		t.Fatal("expected rm -rf / to be blocked, but it was allowed")
	}
	if resp.BlockReason == "" {
		t.Error("expected non-empty BlockReason")
	}
	if resp.MatchedRuleId == "" {
		t.Error("expected non-empty MatchedRuleId")
	}
}

func TestDefenderAllowsLs(t *testing.T) {
	d := testDefender(t)

	resp := d.Validate(context.Background(), &pb.ValidateCommandRequest{
		OperatorId: "op-test",
		Args:       []string{"ls", "-la"},
	})

	if !resp.Allowed {
		t.Fatalf("expected ls -la to be allowed, blocked: %s", resp.BlockReason)
	}
	if resp.Warning != "" {
		t.Logf("warning (unexpected but not fatal): %s", resp.Warning)
	}
}

func TestDefenderBlocksForkBomb(t *testing.T) {
	d := testDefender(t)

	// Classic fork bomb: :(){ :|:& };:
	resp := d.Validate(context.Background(), &pb.ValidateCommandRequest{
		OperatorId: "op-test",
		Args:       []string{":(){ :|:& };:"},
	})

	if resp.Allowed {
		t.Fatal("expected fork bomb to be blocked, but it was allowed")
	}
	if resp.BlockReason == "" {
		t.Error("expected non-empty BlockReason for fork bomb")
	}
}

func TestDefenderBlocksDiskWipe(t *testing.T) {
	d := testDefender(t)

	cases := []struct {
		name string
		args []string
	}{
		{"redirect to sda", []string{"cat", "malware", ">", "/dev/sda"}},
		{"dd zero wipe", []string{"dd", "if=/dev/zero", "of=/dev/sdb"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := d.Validate(context.Background(), &pb.ValidateCommandRequest{
				OperatorId: "op-test",
				Args:       tc.args,
			})
			if resp.Allowed {
				t.Errorf("%s: expected blocked, was allowed", tc.name)
			}
		})
	}
}

func TestDefenderAllowsHarmlessCommands(t *testing.T) {
	d := testDefender(t)

	harmless := [][]string{
		{"whoami"},
		{"id"},
		{"uname", "-a"},
		{"ps", "aux"},
		{"netstat", "-tlnp"},
		{"cat", "/etc/hostname"},
		{"curl", "-s", "http://example.com"},
	}

	for _, args := range harmless {
		resp := d.Validate(context.Background(), &pb.ValidateCommandRequest{
			OperatorId: "op-test",
			Args:       args,
		})
		if !resp.Allowed {
			t.Errorf("args %v: expected allowed, got blocked: %s", args, resp.BlockReason)
		}
	}
}
