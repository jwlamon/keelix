package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jakelamon/keelix/internal/engine"
	"github.com/jakelamon/keelix/internal/model"
	"github.com/spf13/cobra"
)

func newFixCmd() *cobra.Command {
	var (
		sf          scanFlags
		from        string
		interactive bool
	)
	cmd := &cobra.Command{
		Use:   "fix",
		Short: "Guided remediation playbook for the findings",
		Long: `Fix walks through every failing finding and shows the exact change to make.
It never edits your files automatically — it produces a prioritized remediation
playbook you apply yourself.

  keelix fix -c docker-compose.yml -H host --interactive
  keelix fix --from scan.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var result *model.Result
			if from != "" {
				r, err := loadResult(from)
				if err != nil {
					return err
				}
				result = r
			} else {
				in, err := sf.input()
				if err != nil {
					return err
				}
				r, err := engine.Scan(context.Background(), in)
				if err != nil {
					return err
				}
				result = r
			}
			return runFix(result, interactive)
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "use a saved scan JSON instead of scanning")
	f.BoolVarP(&interactive, "interactive", "i", false, "step through fixes one at a time")
	f.StringVarP(&sf.compose, "compose", "c", "", "path to docker-compose.yml")
	f.StringVarP(&sf.host, "host", "H", "", "target host to probe outside-in")
	f.StringVar(&sf.env, "env", "", "path to a .env file")
	f.StringVar(&sf.firewall, "firewall", "", "path to a UFW/iptables rules dump")
	f.StringVar(&sf.proxyConfig, "proxy-config", "", "path to a reverse-proxy config")
	f.StringVar(&sf.domains, "domains", "", "comma-separated extra domains")
	f.StringVar(&sf.intendedPorts, "intended-ports", "", "comma-separated intended-public ports")
	f.BoolVar(&sf.noProbe, "no-probe", false, "disable outside-in probing")
	f.BoolVarP(&sf.verbose, "verbose", "v", false, "verbose progress on stderr")
	cmd.MarkFlagsMutuallyExclusive("from", "compose")
	return cmd
}

func runFix(r *model.Result, interactive bool) error {
	fails := r.Fails()
	if len(fails) == 0 {
		fmt.Println("No issues to fix — posture score is", fmt.Sprintf("%d/100.", r.Score))
		return nil
	}
	fmt.Printf("Remediation playbook for %s — %d issue(s), score %d/100\n\n", r.Target, len(fails), r.Score)
	in := bufio.NewScanner(os.Stdin)
	for i, f := range fails {
		fmt.Printf("[%d/%d] %s  %s\n", i+1, len(fails), f.Severity.Label(), f.Title)
		if f.Service != "" {
			fmt.Printf("       service: %s\n", f.Service)
		}
		if f.Resource != "" {
			fmt.Printf("       resource: %s\n", f.Resource)
		}
		detail := f.Detail
		if f.AIExplanation != "" {
			detail = f.AIExplanation
		}
		fmt.Printf("       why: %s\n", wrap(detail, 72, "            "))
		if f.Fix.Summary != "" {
			fmt.Printf("       fix: %s\n", f.Fix.Summary)
		}
		diff := f.Fix.Diff
		if diff == "" {
			diff = f.AIDiff
		}
		if diff != "" {
			fmt.Println("       --- change ---")
			for _, line := range strings.Split(strings.TrimRight(diff, "\n"), "\n") {
				fmt.Printf("       %s\n", line)
			}
		}
		for _, c := range f.Fix.Commands {
			fmt.Printf("       $ %s\n", c)
		}
		fmt.Println()
		if interactive && i < len(fails)-1 {
			fmt.Print("       press Enter for the next fix (q to quit) ... ")
			if !in.Scan() || strings.TrimSpace(strings.ToLower(in.Text())) == "q" {
				fmt.Println()
				break
			}
			fmt.Println()
		}
	}
	fmt.Println("Re-run `keelix scan` after applying these to confirm the score improves.")
	return nil
}

// wrap soft-wraps s at width, indenting continuation lines with indent.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		if i > 0 && lineLen+1+len(w) > width {
			b.WriteString("\n" + indent)
			lineLen = 0
		} else if i > 0 {
			b.WriteString(" ")
			lineLen++
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
}
