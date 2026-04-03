package console

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// AgentsCmd returns a cobra command that lists connected agents.
func AgentsCmd(client *Client) *cobra.Command {
	return &cobra.Command{
		Use:   "agents",
		Short: "List connected agents with status and metrics",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			infos, err := client.ListAgents(ctx)
			if err != nil {
				return fmt.Errorf("list agents: %w", err)
			}

			rows := make([]AgentRow, 0, len(infos))
			for _, a := range infos {
				mode := "session"
				if a.Mode.String() == "AGENT_MODE_BEACON" {
					mode = "beacon"
				}
				rows = append(rows, AgentRow{
					Hostname:    a.Hostname,
					ID:          shortID(a.AgentId),
					TailscaleIP: a.TailscaleIp,
					Status:      "online",
					Mode:        mode,
					CPU:         "–",
					Mem:         "–",
					Tags:        strings.Join(a.Tags, ","),
				})
			}
			AgentTable(cmd.OutOrStdout(), rows)
			return nil
		},
	}
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
