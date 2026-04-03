package console

import (
	"context"
	"fmt"
	"time"

	pb "github.com/sbu/spectre-c2/pkg/proto"
	"github.com/sbu/spectre-c2/pkg/console/ui"
	"github.com/spf13/cobra"
)

// ScanCmd returns a cobra command that dispatches a distributed SPECTRE port scan.
func ScanCmd(client *Client) *cobra.Command {
	var (
		flagSession string
		flagPorts   string
		flagTimeout int64
	)

	cmd := &cobra.Command{
		Use:   "scan <target-agents> <cidr>",
		Short: "Run SPECTRE port scan across agents (CIDR auto-split)",
		Long: `Distribute a SPECTRE scanner run across agents. The CIDR is
automatically split into N equal sub-ranges, one per targeted agent.
Findings stream back to the server and are merged into the session.

Examples:
  scan @all 10.0.0.0/24
  scan @scanners 192.168.1.0/24 --ports 22,80,443,445
  scan kali-01 10.0.0.5 --session corp-audit`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, cidr := args[0], args[1]
			agents, tags := ui.ParseTargets(target)

			// Build SPECTRE scanner args.
			scanArgs := []string{"spectre-scanner", "--target", cidr, "--session", flagSession}
			if flagPorts != "" {
				scanArgs = append(scanArgs, "--ports", flagPorts)
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(flagTimeout+30)*time.Second)
			defer cancel()

			taskIDs, count, warning, err := client.Dispatch(ctx, flagSession, pb.TaskType_TASK_SPECTRE_SCAN, scanArgs, agents, tags, flagTimeout)
			if err != nil {
				return fmt.Errorf("dispatch scan: %w", err)
			}
			if warning != "" {
				fmt.Fprintln(cmd.OutOrStdout(), ui.WarnStyle.Render("  "+warning))
			}
			printDispatchInfo(cmd.OutOrStdout(), taskIDs, count, fmt.Sprintf("spectre scan %s", cidr))
			fmt.Fprintln(cmd.OutOrStdout(), ui.DimStyle.Render("  Findings will stream to session: "+flagSession))
			return nil
		},
	}
	cmd.Flags().StringVarP(&flagSession, "session", "s", "default", "Session name for findings")
	cmd.Flags().StringVarP(&flagPorts, "ports", "p", "", "Port range (e.g. '22,80,443' or '1-1024')")
	cmd.Flags().Int64Var(&flagTimeout, "timeout", 3600, "Scan timeout in seconds")
	return cmd
}

// ReconCmd returns a cobra command that dispatches SPECTRE recon.
func ReconCmd(client *Client) *cobra.Command {
	var flagSession string

	cmd := &cobra.Command{
		Use:   "recon <target-agent> <scope>",
		Short: "Run SPECTRE recon (DNS/OSINT/crt.sh) on one agent",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, scope := args[0], args[1]
			agents, tags := ui.ParseTargets(target)
			reconArgs := []string{"spectre-recon", "--target", scope, "--session", flagSession}
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			taskIDs, count, _, err := client.Dispatch(ctx, flagSession, pb.TaskType_TASK_SPECTRE_RECON, reconArgs, agents, tags, 120)
			if err != nil {
				return err
			}
			printDispatchInfo(cmd.OutOrStdout(), taskIDs, count, "spectre recon "+scope)
			return nil
		},
	}
	cmd.Flags().StringVarP(&flagSession, "session", "s", "default", "Session name")
	return cmd
}

// FuzzCmd returns a cobra command that dispatches SPECTRE protocol fuzzing.
func FuzzCmd(client *Client) *cobra.Command {
	var (
		flagSession  string
		flagProtocol string
	)
	cmd := &cobra.Command{
		Use:   "fuzz <target-agent> <ip:port>",
		Short: "Run SPECTRE protocol fuzzer on an agent",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, ipport := args[0], args[1]
			agents, tags := ui.ParseTargets(target)
			fuzzArgs := []string{"spectre-fuzzer", "--target", ipport, "--protocol", flagProtocol, "--session", flagSession}
			ctx, cancel := context.WithTimeout(context.Background(), 7200*time.Second)
			defer cancel()
			taskIDs, count, _, err := client.Dispatch(ctx, flagSession, pb.TaskType_TASK_SPECTRE_FUZZ, fuzzArgs, agents, tags, 7200)
			if err != nil {
				return err
			}
			printDispatchInfo(cmd.OutOrStdout(), taskIDs, count, "spectre fuzz "+ipport)
			return nil
		},
	}
	cmd.Flags().StringVarP(&flagSession, "session", "s", "default", "Session name")
	cmd.Flags().StringVarP(&flagProtocol, "protocol", "P", "tcp_raw", "Fuzzer protocol")
	return cmd
}
