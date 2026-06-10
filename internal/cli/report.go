package cli

import (
	"context"

	"github.com/jakelamon/keelix/internal/engine"
	"github.com/spf13/cobra"
)

func newReportCmd() *cobra.Command {
	var (
		sf     scanFlags
		from   string
		format string
		output string
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a Security Posture Report (Markdown/HTML/PDF)",
		Long: `Report produces the audit-ready Security Posture Report: cover page and
attestation, executive summary, findings with control mappings, a control-
coverage matrix (SOC 2 / ISO 27001 / CIS Docker), a remediation appendix, and a
methodology statement.

Run a fresh scan, or render from a saved scan JSON:
  keelix report -c docker-compose.yml -H host --format pdf -o posture.pdf
  keelix report --from scan.json --format md -o posture.md`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format == "" {
				format = "md"
			}
			if from != "" {
				r, err := loadResult(from)
				if err != nil {
					return err
				}
				return writeReport(r, format, output)
			}
			in, err := sf.input()
			if err != nil {
				return err
			}
			r, err := engine.Scan(context.Background(), in)
			if err != nil {
				return err
			}
			return writeReport(r, format, output)
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "render from a previously saved scan JSON instead of scanning")
	f.StringVar(&format, "format", "md", "report format: md|html|pdf")
	f.StringVarP(&output, "output", "o", "", "output file (default keelix-report.<ext>)")
	f.StringVarP(&sf.compose, "compose", "c", "", "path to docker-compose.yml")
	f.StringVarP(&sf.host, "host", "H", "", "target host to probe outside-in")
	f.StringVar(&sf.env, "env", "", "path to a .env file")
	f.StringVar(&sf.firewall, "firewall", "", "path to a UFW/iptables rules dump")
	f.StringVar(&sf.proxyConfig, "proxy-config", "", "path to a reverse-proxy config")
	f.StringVar(&sf.domains, "domains", "", "comma-separated extra domains")
	f.StringVar(&sf.intendedPorts, "intended-ports", "", "comma-separated intended-public ports")
	f.BoolVar(&sf.noProbe, "no-probe", false, "disable outside-in probing")
	f.BoolVar(&sf.ai, "ai", false, "enrich via the Claude API (needs ANTHROPIC_API_KEY)")
	f.BoolVarP(&sf.verbose, "verbose", "v", false, "verbose progress on stderr")
	f.StringVar(&sf.policy, "policy", "", "path to a JSON policy file for org-defined custom checks")
	f.StringVar(&sf.brandName, "brand-name", "", "product name shown in reports (default \"Keelix\")")
	cmd.MarkFlagsMutuallyExclusive("from", "compose")
	return cmd
}
