package console

import (
	"context"
	"fmt"

	rfconsole "github.com/reeflective/console"
	pb "github.com/sbu/spectre-c2/pkg/proto"
	"github.com/sbu/spectre-c2/pkg/db"
	"github.com/spf13/cobra"
)

const banner = `
  ╔══════════════════════════════════════════════╗
  ║   SPECTRE-C2  Fleet Operator Console v0.1    ║
  ║   Sliver-class gRPC · Session+Beacon · AI    ║
  ║   Type 'help' for commands · Tab to complete ║
  ╚══════════════════════════════════════════════╝`

// Start launches the interactive operator console.
// serverAddr: gRPC server address e.g. "127.0.0.1:7443"
// operatorID: unique operator name
// store: local SQLite store (for db command passthrough)
func Start(serverAddr, operatorID string, store *db.Store) error {
	fmt.Println(banner)
	fmt.Printf("  Connecting to %s...\n", serverAddr)

	client, err := Connect(serverAddr, operatorID)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	defer client.Close()

	fmt.Printf("  Connected as operator: %s\n\n", operatorID)

	app := rfconsole.New("spectre")

	// Set fish-like syntax highlighter on the underlying readline shell.
	app.Shell().SyntaxHighlighter = Highlight

	// Build command tree and register with the default menu.
	mainMenu := app.ActiveMenu()
	mainMenu.SetCommands(func() *cobra.Command {
		root := &cobra.Command{
			Use:   "spectre",
			Short: "SPECTRE-C2 Fleet Console",
		}
		root.AddCommand(
			AgentsCmd(client),
			ExecCmd(client),
			ScanCmd(client),
			ReconCmd(client),
			FuzzCmd(client),
			SessionsCmd(client),
			FindingsCmd(client),
			DBCmd(store),
		)
		return root
	})

	// Background goroutine: subscribe to server events and print transient notifications.
	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()

	go func() {
		_ = client.Subscribe(subCtx, func(evt *pb.Event) {
			switch evt.Type {
			case pb.EventType_EVENT_AGENT_CONNECTED:
				app.TransientPrintf("\n  Agent connected:    %s\n", evt.AgentId)
			case pb.EventType_EVENT_AGENT_DISCONNECTED:
				app.TransientPrintf("\n  Agent disconnected: %s\n", evt.AgentId)
			case pb.EventType_EVENT_TASK_COMPLETED:
				app.TransientPrintf("\n  Task completed on:  %s\n", evt.AgentId)
			case pb.EventType_EVENT_FINDING_NEW:
				app.TransientPrintf("\n  New finding on:     %s\n", evt.AgentId)
			}
		})
	}()

	return app.Start()
}
