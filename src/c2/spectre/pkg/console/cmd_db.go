package console

import (
	"fmt"
	"strings"

	"github.com/sbu/spectre-c2/pkg/console/ui"
	"github.com/sbu/spectre-c2/pkg/db"
	"github.com/spf13/cobra"
)

// DBCmd returns a cobra command that runs raw SQLite queries against the local store.
func DBCmd(store *db.Store) *cobra.Command {
	return &cobra.Command{
		Use:   "db <sql>",
		Short: "Run a raw SQLite query against the local state store",
		Long: `Execute any SQL against the local SQLite database.
Read-only queries are recommended.

Examples:
  db "SELECT hostname, status FROM agents"
  db "SELECT severity, COUNT(*) FROM findings GROUP BY severity"`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := args[0]
			rows, err := store.DB.Query(query)
			if err != nil {
				return fmt.Errorf("query: %w", err)
			}
			defer rows.Close()

			cols, _ := rows.Columns()
			out := cmd.OutOrStdout()
			sep := ui.DimStyle.Render("  " + strings.Repeat("─", 60))
			fmt.Fprintln(out, ui.HeaderStyle.Render("  "+joinCols(cols)))
			fmt.Fprintln(out, sep)

			vals := make([]interface{}, len(cols))
			ptrs := make([]interface{}, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			for rows.Next() {
				if err := rows.Scan(ptrs...); err != nil {
					return fmt.Errorf("scan: %w", err)
				}
				fmt.Fprintln(out, "  "+joinVals(vals))
			}
			return rows.Err()
		},
	}
}

func joinCols(cols []string) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = fmt.Sprintf("%-16s", c)
	}
	return strings.Join(parts, "  │  ")
}

func joinVals(vals []interface{}) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%-16v", v)
	}
	return strings.Join(parts, "  │  ")
}
