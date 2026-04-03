package console

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	pb "github.com/sbu/spectre-c2/pkg/proto"
	"github.com/sbu/spectre-c2/pkg/console/ui"
	"github.com/spf13/cobra"
)

// ExecCmd returns a cobra command that dispatches a shell command to agents.
func ExecCmd(client *Client) *cobra.Command {
	var (
		flagSession string
		flagTimeout int64
	)

	cmd := &cobra.Command{
		Use:   "exec <target> <command...>",
		Short: "Execute a shell command on one or more agents",
		Long: `Execute a shell command on agent(s).

Targets:
  @all          All connected agents
  @scanners     Agents tagged "scanners"
  kali-01       Specific agent by hostname/ID
  kali-01,kali-02  Multiple agents (comma-separated)

Examples:
  exec @all uptime
  exec @scanners "nuclei --version"
  exec kali-03 "ps aux | grep nmap"`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			shellArgs := args[1:]
			agents, tags := ui.ParseTargets(target)

			// Session Defender check — non-fatal if server is unreachable.
			validateResp, err := client.ValidateCommand(context.Background(), pb.TaskType_TASK_EXEC, shellArgs, target)
			if err == nil {
				if !validateResp.Allowed {
					return fmt.Errorf("Session Defender BLOCKED: %s", validateResp.BlockReason)
				}
				if validateResp.Warning != "" {
					fmt.Fprintln(cmd.OutOrStdout(), ui.WarnStyle.Render("  Defender: "+validateResp.Warning))
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(flagTimeout+10)*time.Second)
			defer cancel()

			taskIDs, count, warning, err := client.Dispatch(ctx, flagSession, pb.TaskType_TASK_EXEC, shellArgs, agents, tags, flagTimeout)
			if err != nil {
				return fmt.Errorf("dispatch: %w", err)
			}
			if warning != "" {
				fmt.Fprintln(cmd.OutOrStdout(), ui.WarnStyle.Render("  "+warning))
			}
			printDispatchInfo(cmd.OutOrStdout(), taskIDs, count, strings.Join(shellArgs, " "))
			return nil
		},
	}
	cmd.Flags().StringVarP(&flagSession, "session", "s", "default", "Session name")
	cmd.Flags().Int64Var(&flagTimeout, "timeout", 60, "Task timeout in seconds")
	return cmd
}

// printDispatchInfo writes a formatted dispatch summary box to out.
func printDispatchInfo(out io.Writer, taskIDs []string, count int32, cmdLine string) {
	fmt.Fprintf(out, "\n  ╭─ Dispatched ────────────────────────────\n")
	fmt.Fprintf(out, "  │  Command: %s\n", cmdLine)
	fmt.Fprintf(out, "  │  Agents:  %d\n", count)
	for _, id := range taskIDs {
		short := id
		if len(id) > 8 {
			short = id[:8]
		}
		fmt.Fprintf(out, "  │  Task:    %s…\n", short)
	}
	fmt.Fprintf(out, "  ╰─────────────────────────────────────────\n\n")
}
