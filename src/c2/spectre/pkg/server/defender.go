package server

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/sbu/spectre-c2/pkg/db"
	pb "github.com/sbu/spectre-c2/pkg/proto"
)

// Defender validates operator commands before they are dispatched to agents.
// Inspired by Villain's Session Defender, it checks each command against a
// set of regex rules stored in the database. Rules can either block a command
// entirely or issue a warning while allowing execution.
type Defender struct {
	store *db.Store
}

// NewDefender creates a Defender backed by the given database store.
func NewDefender(store *db.Store) *Defender {
	return &Defender{store: store}
}

// Validate checks a command against all configured rules and returns a
// ValidateCommandResponse indicating whether the command is allowed.
//
// Evaluation order:
//  1. Fetch rules from DB (on error: allow with warning).
//  2. Build a single command-line string from req.Args.
//  3. Test each rule's regex against the command string.
//  4. First match wins: blocked rules return immediately; warn rules return
//     immediately with Allowed=true.
//  5. No match → Allowed=true, no warning.
func (d *Defender) Validate(ctx context.Context, req *pb.ValidateCommandRequest) *pb.ValidateCommandResponse {
	rules, err := d.store.GetDefenderRules()
	if err != nil {
		// On DB error, allow but surface the problem to the operator.
		return &pb.ValidateCommandResponse{
			Allowed: true,
			Warning: fmt.Sprintf("Defender DB error (allowing): %v", err),
		}
	}

	cmdLine := strings.Join(req.Args, " ")

	for _, rule := range rules {
		re, compileErr := regexp.Compile(rule.Pattern)
		if compileErr != nil {
			// Bad regex in DB — skip and continue.
			continue
		}
		if re.MatchString(cmdLine) {
			if rule.IsBlocked {
				return &pb.ValidateCommandResponse{
					Allowed:       false,
					BlockReason:   fmt.Sprintf("[BLOCKED] %s (rule: %s)", rule.Description, rule.ID),
					MatchedRuleId: rule.ID,
				}
			}
			return &pb.ValidateCommandResponse{
				Allowed:       true,
				Warning:       fmt.Sprintf("[WARN] %s (rule: %s)", rule.Description, rule.ID),
				MatchedRuleId: rule.ID,
			}
		}
	}

	return &pb.ValidateCommandResponse{Allowed: true}
}
