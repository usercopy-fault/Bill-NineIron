package console

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sbu/spectre-c2/pkg/console/ui"
	"github.com/spf13/cobra"
)

// SessionsCmd returns a cobra command that lists research sessions.
func SessionsCmd(client *Client) *cobra.Command {
	return &cobra.Command{
		Use:   "sessions",
		Short: "List research sessions with finding counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			sessions, err := client.GetSessions(ctx)
			if err != nil {
				return err
			}
			if len(sessions) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), ui.WarnStyle.Render("  No sessions found."))
				return nil
			}
			out := cmd.OutOrStdout()
			sep := ui.DimStyle.Render("  " + strings.Repeat("─", 80))
			fmt.Fprintln(out, ui.HeaderStyle.Render(fmt.Sprintf(
				"  %-30s  %-12s  %-8s  %-8s  %s",
				"SESSION ID", "STATUS", "FINDINGS", "TASKS", "CREATED",
			)))
			fmt.Fprintln(out, sep)
			for _, s := range sessions {
				fmt.Fprintf(out, "  %-30s  %-12s  %-8d  %-8d  %s\n",
					s.SessionId, s.Status, s.FindingCount, s.TaskCount, s.CreatedAt)
			}
			return nil
		},
	}
}

// FindingsCmd returns a cobra command that queries findings for a session.
func FindingsCmd(client *Client) *cobra.Command {
	var (
		flagSession  string
		flagSeverity string
	)
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "Query findings for a session",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			pbFindings, err := client.GetFindings(ctx, flagSession, flagSeverity)
			if err != nil {
				return err
			}
			rows := make([]FindingRow, 0, len(pbFindings))
			for _, f := range pbFindings {
				rows = append(rows, FindingRow{
					ID:       f.FindingId,
					HostIP:   f.HostIp,
					Port:     int(f.Port),
					Severity: f.Severity,
					Title:    f.Title,
					CVSS:     f.CvssScore,
				})
			}
			FindingsTable(cmd.OutOrStdout(), rows)
			return nil
		},
	}
	cmd.Flags().StringVarP(&flagSession, "session", "s", "", "Session ID (required)")
	cmd.Flags().StringVar(&flagSeverity, "severity", "", "Filter: critical|high|medium|low|info")
	cmd.MarkFlagRequired("session")
	return cmd
}
