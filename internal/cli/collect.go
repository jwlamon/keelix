package cli

import (
	"encoding/json"
	"os"

	"github.com/jakelamon/keelix/internal/collect"
	"github.com/jakelamon/keelix/internal/model"
	"github.com/spf13/cobra"
)

func newCollectCmd() *cobra.Command {
	var (
		privileged bool
		output     string
	)
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Gather inside-out host signals and write them as JSON",
		Long: `Collect runs the inside-out signal collectors (listening sockets,
file modes, config facts, processes, package state, firewall state) on the
current host and writes a Signals document. Feed it back into a scan with
'keelix scan --signals <file>' to correlate exposure from the host's point of view.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sig, err := collect.Collect(collect.Options{Privileged: privileged})
			if err != nil {
				return err
			}
			return writeSignals(sig, output)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&privileged, "privileged", false, "run privileged collectors (requires root for full coverage)")
	f.StringVarP(&output, "output", "o", "", "write Signals JSON to this file instead of stdout")
	return cmd
}

// writeSignals encodes Signals as indented JSON to stdout or the given file,
// mirroring writeJSON in scan.go.
func writeSignals(s *model.Signals, output string) error {
	if output == "" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}
	f, err := os.Create(output) // #nosec G304 -- output path is an operator-supplied CLI flag; local CLI writing the user's own file
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
