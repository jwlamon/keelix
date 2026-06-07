package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/score/regrade"
	"github.com/spf13/cobra"
)

func newRegradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "regrade <glob-or-dir-of-scan-json>...",
		Short: "Replay saved scans through v1 and v2 scoring and report grade transitions",
		Long: `Regrade loads previously saved scan JSON files and recomputes each one
under both the current (v1) and the v2 scoring engines, then prints a transition
table and the headline count of boxes that re-grade GREEN->RED.

Run this offline before flipping v2 to the default scoring model:
  keelix regrade ./scans/                 # every *.json in a directory
  keelix regrade 'scans/*.json'           # an explicit glob
  keelix regrade a.json b.json c.json     # explicit files`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegrade(cmd.OutOrStdout(), args)
		},
	}
}

// collectScanPaths expands each arg into scan-JSON paths. An arg that is a
// directory contributes every *.json inside it; any other arg is treated as a
// filepath glob (a plain filename is a glob that matches itself). Results are
// de-duplicated and sorted for deterministic output.
func collectScanPaths(args []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, a := range args {
		info, err := os.Stat(a)
		if err == nil && info.IsDir() {
			matches, err := filepath.Glob(filepath.Join(a, "*.json"))
			if err != nil {
				return nil, err
			}
			for _, m := range matches {
				add(m)
			}
			continue
		}
		matches, err := filepath.Glob(a)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no files match %q", a)
		}
		for _, m := range matches {
			add(m)
		}
	}
	sort.Strings(out)
	return out, nil
}

// runRegrade loads every scan JSON named by args, regrades the batch, and
// writes the summary to w.
func runRegrade(w io.Writer, args []string) error {
	paths, err := collectScanPaths(args)
	if err != nil {
		return err
	}
	results := make([]model.Result, 0, len(paths))
	for _, p := range paths {
		r, err := loadResult(p)
		if err != nil {
			return fmt.Errorf("loading %s: %w", p, err)
		}
		results = append(results, *r)
	}
	rep := regrade.Regrade(results)
	fmt.Fprint(w, rep.Summary())
	return nil
}
