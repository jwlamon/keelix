package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/jakelamon/keelix/internal/engine"
	"github.com/jakelamon/keelix/internal/report"
	"github.com/spf13/cobra"
)

// tokenFromEnv returns the cloud API key from the environment.
func tokenFromEnv() string { return os.Getenv("KEELIX_API_KEY") }

// cloudURLFromEnv returns the cloud base URL from the environment.
func cloudURLFromEnv() string { return os.Getenv("KEELIX_CLOUD_URL") }

func newPushCmd() *cobra.Command {
	var (
		sf       scanFlags
		hostID   string
		cloudURL string
	)
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Scan and push the result to Keelix Cloud",
		Long: `Push runs a local scan and uploads the result to Keelix Cloud.
It requires a cloud API key (kx_...) set via KEELIX_API_KEY and the
cloud base URL set via KEELIX_CLOUD_URL or --cloud-url.

The CLI itself remains free and open-source; push uses only the cloud API key
you created in Settings → API Keys.

Examples:
  keelix push -c docker-compose.yml -H myhost --host-id <uuid>
  KEELIX_API_KEY=kx_... KEELIX_CLOUD_URL=https://app.example.com \
    keelix push -c docker-compose.yml --host-id <uuid>`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if hostID == "" {
				return fmt.Errorf("--host-id is required")
			}
			token := tokenFromEnv()
			if token == "" {
				return exitError{code: 1, msg: "invalid or missing KEELIX_API_KEY"}
			}
			if cloudURL == "" {
				cloudURL = cloudURLFromEnv()
			}
			if cloudURL == "" {
				return exitError{code: 1, msg: "--cloud-url or KEELIX_CLOUD_URL is required"}
			}

			in, err := sf.input()
			if err != nil {
				return err
			}
			result, err := engine.Scan(context.Background(), in)
			if err != nil {
				return err
			}

			// Marshal using the same JSON the report.JSON writer uses.
			var buf bytes.Buffer
			if err := report.JSON(&buf, result); err != nil {
				return fmt.Errorf("marshal scan result: %w", err)
			}

			// Inject host_id into the JSON payload.
			var payload map[string]any
			if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
				return fmt.Errorf("unmarshal scan result: %w", err)
			}
			payload["host_id"] = hostID
			jsonBody, err := json.Marshal(payload)
			if err != nil {
				return fmt.Errorf("marshal payload: %w", err)
			}

			status, body, err := pushResult(cloudURL, token, jsonBody)
			if err != nil {
				return fmt.Errorf("push failed: %w", err)
			}

			switch {
			case status == 201 || status == 200:
				var resp struct {
					ScanID string `json:"scan_id"`
					ID     string `json:"id"`
				}
				_ = json.Unmarshal([]byte(body), &resp)
				id := resp.ScanID
				if id == "" {
					id = resp.ID
				}
				fmt.Printf("✓ pushed scan %s\n", id)
				return nil
			case status == 402:
				return exitError{code: 1, msg: "plan limit reached — upgrade at " + cloudURL + "/app/billing"}
			case status == 429:
				return exitError{code: 1, msg: "monthly scan quota exceeded — upgrade at " + cloudURL + "/app/billing"}
			case status == 401:
				return exitError{code: 1, msg: "invalid or missing KEELIX_API_KEY"}
			default:
				return exitError{code: 1, msg: fmt.Sprintf("push failed (%d): %s", status, body)}
			}
		},
	}
	f := cmd.Flags()
	f.StringVar(&hostID, "host-id", "", "Keelix Cloud host UUID (required)")
	f.StringVar(&cloudURL, "cloud-url", "", "Keelix Cloud base URL (default: $KEELIX_CLOUD_URL)")
	f.StringVarP(&sf.compose, "compose", "c", "", "path to docker-compose.yml (required)")
	f.StringVarP(&sf.host, "host", "H", "", "target host to probe outside-in")
	f.StringVar(&sf.env, "env", "", "path to a .env file")
	f.StringVar(&sf.firewall, "firewall", "", "path to a UFW/iptables rules dump")
	f.StringVar(&sf.proxyConfig, "proxy-config", "", "path to a reverse-proxy config")
	f.StringVar(&sf.domains, "domains", "", "comma-separated extra domains")
	f.StringVar(&sf.intendedPorts, "intended-ports", "", "comma-separated intended-public ports")
	f.BoolVar(&sf.noProbe, "no-probe", false, "disable outside-in probing (static analysis only)")
	f.BoolVar(&sf.ai, "ai", false, "enrich findings via the Claude API (needs ANTHROPIC_API_KEY)")
	f.DurationVar(&sf.timeout, "timeout", 0, "per-connection probe timeout (default 3s)")
	f.BoolVarP(&sf.verbose, "verbose", "v", false, "verbose progress on stderr")
	f.StringVar(&sf.policy, "policy", "", "path to a JSON policy file for org-defined custom checks")
	return cmd
}

// pushResult posts jsonBody to <cloudURL>/api/scans and returns the HTTP status,
// response body, and any transport error. It is a separate helper to enable
// unit testing without running a full scan.
func pushResult(cloudURL, token string, jsonBody []byte) (status int, body string, err error) {
	req, err := http.NewRequest(http.MethodPost, cloudURL+"/api/scans", bytes.NewReader(jsonBody))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}
