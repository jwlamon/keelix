// Package cli implements the keelix command-line interface.
package cli

import (
	"fmt"
	"os"

	"github.com/jakelamon/keelix/internal/version"
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "keelix",
		Short: "Pre-deployment security gate for self-hosted Docker stacks",
		Long: `Keelix audits a Docker Compose stack: it probes what is actually
reachable from the internet, detects firewall bypass / proxy / container /
secrets / TLS / DNS misconfigurations, scores your posture 0-100, and produces
an audit-ready Security Posture Report mapped to SOC 2, ISO 27001, and the CIS
Docker Benchmark.`,
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCmd())
	root.AddCommand(newCollectCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newFixCmd())
	root.AddCommand(newPushCmd())
	root.AddCommand(newRegradeCmd())
	root.AddCommand(newVersionCmd())
	root.AddCommand(newSandboxChildCmd())
	return root
}

// Execute runs the root command and returns a process exit code.
func Execute() int {
	if err := newRootCmd().Execute(); err != nil {
		if ec, ok := err.(exitError); ok {
			if ec.msg != "" {
				fmt.Fprintln(os.Stderr, "keelix:", ec.msg)
			}
			return ec.code
		}
		fmt.Fprintln(os.Stderr, "keelix:", err)
		return 1
	}
	return 0
}

// exitError lets commands request a specific process exit code (used by --ci).
type exitError struct {
	code int
	msg  string
}

func (e exitError) Error() string { return e.msg }

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "keelix %s\ncommit: %s\nbuilt:  %s\n",
				version.Version, version.Commit, version.Date)
		},
	}
}
