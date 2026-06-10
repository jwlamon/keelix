package firewall

import (
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/correlate"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&fw006{}) }

type fw006 struct{}

func (c *fw006) ID() string              { return catalog.Get("FW006").ID }
func (c *fw006) Title() string           { return catalog.Get("FW006").Title }
func (c *fw006) Group() model.CheckGroup { return catalog.Get("FW006").Group }

// kubeletComms are the process names that identify a k3s or kubelet server.
var kubeletComms = []string{"k3s", "k3s-server", "kubelet", "hyperkube"}

func (c *fw006) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("FW006")}
	}
	if ctx.Collector.Platform.OS == "darwin" {
		return []model.Finding{notAssessed("FW006")}
	}

	for _, proc := range ctx.Collector.Processes {
		if !isKubeletProcess(proc.Comm) {
			continue
		}
		reason, fires := kubeletAnonAuth(proc.Args)
		if !fires {
			continue
		}
		f := catalog.Get("FW006").Finding()
		f.Resource = proc.Comm
		// Derive ExposureClass from the kubelet's bind address.
		// --address or --bind-address overrides the default (0.0.0.0); when
		// absent the kubelet listens on all interfaces => ExposureInternet.
		f.ExposureClass = correlate.BindClass(kubeletBindAddr(proc.Args))
		f.Evidence = reason
		f.Fix = model.Fix{
			Summary: "Set --anonymous-auth=false and --authorization-mode=Webhook on the kubelet to require authenticated API calls.",
			Commands: []string{
				"# Add to kubelet args or /etc/kubernetes/kubelet.conf:",
				"--anonymous-auth=false",
				"--authorization-mode=Webhook",
			},
		}
		return []model.Finding{f}
	}

	return []model.Finding{catalog.Get("FW006").Pass("No k3s/kubelet process found with anonymous auth enabled.")}
}

func isKubeletProcess(comm string) bool {
	lower := strings.ToLower(comm)
	for _, k := range kubeletComms {
		if lower == k {
			return true
		}
	}
	return false
}

// kubeletBindAddr extracts the bind address from a kubelet/k3s arg list.
// It checks --address=<addr> and --bind-address=<addr> (both forms: key=value
// and key <space> value). When neither is present the default is "0.0.0.0"
// (the kubelet binds to all interfaces).
func kubeletBindAddr(args []string) string {
	for i, arg := range args {
		for _, flag := range []string{"--address=", "--bind-address="} {
			if strings.HasPrefix(arg, flag) {
				return arg[len(flag):]
			}
		}
		for _, flag := range []string{"--address", "--bind-address"} {
			if arg == flag && i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return "0.0.0.0"
}

// unwrapKubeletArgs expands k3s --kubelet-arg=<flag>=<value> entries into the
// equivalent native --<flag>=<value> form. All other args are passed through
// unchanged. This allows kubeletAnonAuth to assess k3s processes identically to
// raw kubelet processes.
//
// Example: ["k3s", "server", "--kubelet-arg=anonymous-auth=true"] becomes
// ["k3s", "server", "--anonymous-auth=true"].
func unwrapKubeletArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.HasPrefix(arg, "--kubelet-arg=") {
			inner := strings.TrimPrefix(arg, "--kubelet-arg=")
			if !strings.HasPrefix(inner, "--") {
				inner = "--" + inner
			}
			out = append(out, inner)
		} else {
			out = append(out, arg)
		}
	}
	return out
}

// kubeletAnonAuth returns (reason, true) when the arg list indicates anonymous
// auth is enabled. Both "key=value" and "key value" (space-separated) argument
// forms are supported for --anonymous-auth and --authorization-mode, mirroring
// the kubeletBindAddr two-token pattern.
//
// k3s wraps kubelet flags as --kubelet-arg=<flag>=<value>; unwrapKubeletArgs
// expands these before matching so k3s kubelets are assessed identically to raw
// kubelet processes.
//
// Correct semantics (R3-1):
//   - PASS when --anonymous-auth=false (anon rejected at authN, authz mode irrelevant).
//   - FAIL when anonAuth is NOT explicitly false AND the authz-mode list contains
//     AlwaysAllow (every request passes authz, including anonymous ones).
//   - FAIL when anonAuth is NOT explicitly false AND --anonymous-auth=true (anon
//     explicitly requested).
//   - PASS (not fired) when neither flag is present: require a confirmed-open
//     signal; do not fire on absence alone to avoid version-dependent false positives.
//
// Value comparisons are case-insensitive (pflag accepts True/TRUE/false/FALSE).
// When a flag appears multiple times the last occurrence wins (flag parsing convention).
func kubeletAnonAuth(args []string) (string, bool) {
	args = unwrapKubeletArgs(args)

	// anonVal tracks the last-seen value of --anonymous-auth (lowercased); "" = absent.
	anonVal := ""
	// authModeVal is the value of --authorization-mode (last occurrence); "" = absent.
	authModeVal := ""
	// authModePresent tracks whether the flag was seen at all.
	authModePresent := false

	for i, arg := range args {
		// --anonymous-auth=<value> (equals form) — last-wins via overwrite.
		if strings.HasPrefix(arg, "--anonymous-auth=") {
			anonVal = strings.ToLower(strings.TrimPrefix(arg, "--anonymous-auth="))
			continue
		}
		// --anonymous-auth <value> (space form) — last-wins via overwrite.
		if arg == "--anonymous-auth" && i+1 < len(args) {
			anonVal = strings.ToLower(args[i+1])
			continue
		}
		// --authorization-mode=<value> (equals form) — last-wins via overwrite.
		if strings.HasPrefix(arg, "--authorization-mode=") {
			authModePresent = true
			authModeVal = strings.TrimPrefix(arg, "--authorization-mode=")
			continue
		}
		// --authorization-mode <value> (space form) — last-wins via overwrite.
		if arg == "--authorization-mode" && i+1 < len(args) {
			authModePresent = true
			authModeVal = args[i+1]
			continue
		}
	}

	// Resolve the anonymous-auth state from the last-seen value.
	anonExplicitFalse := anonVal == "false"
	anonExplicitTrue := anonVal == "true"

	// When anon is explicitly disabled at authN, the kubelet rejects anonymous
	// requests before they reach the authz layer — safe regardless of authz mode.
	if anonExplicitFalse {
		return "", false
	}

	// AlwaysAllow in the authz-mode list (comma-delimited) means every request —
	// including anonymous — is authorized. Fire regardless of anon flag value.
	if authModePresent {
		for _, mode := range strings.Split(authModeVal, ",") {
			if strings.TrimSpace(mode) == "AlwaysAllow" {
				return "kubelet is started with --authorization-mode=AlwaysAllow; every request is authorized regardless of authentication state", true
			}
		}
		// Real authorizer (Webhook/RBAC/Node/etc.) without AlwaysAllow.
		return "", false
	}

	// Neither flag is present: do not fire on absence alone.
	// Require a confirmed-open signal (--anonymous-auth=true) to avoid false
	// positives on kubelets where defaults changed across versions.
	if anonExplicitTrue {
		return "kubelet is started with --anonymous-auth=true; the kubelet API accepts unauthenticated requests", true
	}

	// No confirmed-open signal — pass.
	return "", false
}
