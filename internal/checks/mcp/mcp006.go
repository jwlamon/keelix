// Package mcp — MCP006: Unvetted MCP server provenance.
package mcp

import (
	"fmt"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&mcp006{}) }

type mcp006 struct{}

func (c *mcp006) ID() string              { return "MCP006" }
func (c *mcp006) Title() string           { return catalog.Get("MCP006").Title }
func (c *mcp006) Group() model.CheckGroup { return catalog.Get("MCP006").Group }

// verifiedNPMScopes are npm org scopes recognized as trusted first-party
// AI/MCP-vendor publishers. npm org scopes are access-controlled namespaces
// (only the owning org can publish under them), so membership is a genuine
// provenance signal: an arg with one of these prefixes is treated as vetted.
//
// Deliberately narrow: cloud/platform megascopes (@aws/, @google/, @microsoft/,
// @azure/, @cloudflare/, @github/) are NOT listed — they publish a huge,
// unrelated surface, so "from that org" is too weak a provenance signal for an
// MCP server. The scopes below are focused AI/MCP-ecosystem vendors whose
// published packages are reasonably treated as vetted-origin.
var verifiedNPMScopes = []string{
	"@modelcontextprotocol/",
	"@anthropic/",
	"@anthropic-ai/",
	"@openai/",
}

// verifiedRegistryPublishers are bare (unscoped) package names published through
// the official MCP registry's verified-publisher program. Matched exactly.
// The version-specifier suffix (==x.y.z or @x.y.z) is stripped before lookup.
var verifiedRegistryPublishers = map[string]bool{
	"mcp-server-filesystem": true,
	"mcp-server-git":        true,
	"mcp-server-fetch":      true,
	"mcp-server-sqlite":     true,
	"server-everything":     true,
}

// verifiedOCIImages are pinned-digest OCI MCP images from trusted registries.
// An arg is vetted only when it is BOTH on this base list AND pinned to a digest
// (@sha256:...), so a floating tag of a trusted image is still flagged.
var verifiedOCIImages = map[string]bool{
	"ghcr.io/modelcontextprotocol/server-filesystem": true,
	"ghcr.io/modelcontextprotocol/server-git":        true,
	"docker.io/mcp/server-fetch":                     true,
}

// ociRegistryPrefixes are hostname prefixes that identify an arg as an OCI image
// reference rather than an npm/pypi/registry package name.
var ociRegistryPrefixes = []string{
	"ghcr.io/",
	"docker.io/",
	"registry.hub.docker.com/",
	"gcr.io/",
	"public.ecr.aws/",
	"mcr.microsoft.com/",
}

// registrySchemes are URL-like prefixes that identify a package manager or
// registry scheme embedded in an arg. They must be stripped before scope/name
// analysis so that "jsr:@scope/pkg" and "@scope/pkg" are treated identically.
// SF-4 (b).
var registrySchemes = []string{"jsr:", "npm:", "npx:"}

// stripRegistryScheme removes a leading registry scheme prefix (e.g. "jsr:",
// "npm:", "npx:") from arg if present, returning the bare package ref.
func stripRegistryScheme(arg string) string {
	for _, scheme := range registrySchemes {
		if strings.HasPrefix(arg, scheme) {
			return arg[len(scheme):]
		}
	}
	return arg
}

// containerRuntimes lists process commands that are container runtimes whose
// args follow the pattern: <subcommand> [flags…] <image-ref> [cmd…].
// SF-4 (a).
var containerRuntimes = map[string]bool{
	"docker":  true,
	"podman":  true,
	"nerdctl": true,
}

// containerSubcommands are docker/podman subcommands or flag prefixes that
// precede the image reference in a "docker run …" invocation. Any arg in this
// set (or starting with "-") is skipped when looking for the image reference.
// SF-4 (a).
var containerSubcommands = map[string]bool{
	"run":    true,
	"exec":   true,
	"create": true,
	"start":  true,
	"pull":   true,
	"push":   true,
	"build":  true,
	"tag":    true,
}

// containerValueFlags are docker/podman flags that consume the next argument as
// their value (e.g. `-e FOO=BAR`, `--name mycontainer`, `-v /host:/container`).
// When one of these flags is encountered in container mode, the following arg
// must also be skipped — it is the flag's value, not the image reference.
// SR-3.
var containerValueFlags = map[string]bool{
	"-e":           true,
	"--env":        true,
	"-v":           true,
	"--volume":     true,
	"--name":       true,
	"-p":           true,
	"--publish":    true,
	"-u":           true,
	"--user":       true,
	"--network":    true,
	"-w":           true,
	"--workdir":    true,
	"--entrypoint": true,
	"-l":           true,
	"--label":      true,
	"--mount":      true,
	"-h":           true,
	"--hostname":   true,
	"--log-driver": true,
	"--log-opt":    true,
	"--cidfile":    true,
}

// isContainerRuntime reports whether cmd is a known container runtime binary.
func isContainerRuntime(cmd string) bool {
	return containerRuntimes[strings.ToLower(cmd)]
}

// isContainerSubcmdOrFlag reports whether an arg is a container subcommand or
// a flag (starts with "-"), and therefore should be skipped when searching for
// the image reference in a container-runtime invocation.
func isContainerSubcmdOrFlag(arg string) bool {
	return strings.HasPrefix(arg, "-") || containerSubcommands[arg]
}

// isContainerValueFlag reports whether a flag is one that consumes the next
// argument as its value (rather than being a boolean flag). When true, the arg
// immediately following this flag must also be skipped when searching for the
// image reference in a container-runtime invocation. SR-3.
func isContainerValueFlag(flag string) bool {
	return containerValueFlags[flag]
}

// isVerifiedProvenance reports whether an MCP server launch arg comes from a
// recognized verified source: a verified npm scope, an official-registry
// publisher package, or a pinned-digest trusted OCI image.
//
// SF-4 (b): a leading registry scheme (jsr:, npm:, npx:) is stripped before
// scope/name analysis so "jsr:@scope/pkg" is treated like "@scope/pkg".
func isVerifiedProvenance(arg string) bool {
	// Strip registry scheme prefix before any analysis (SF-4 b).
	bare := stripRegistryScheme(arg)

	if strings.HasPrefix(bare, "@") {
		for _, scope := range verifiedNPMScopes {
			if strings.HasPrefix(bare, scope) {
				return true
			}
		}
		return false
	}
	if verifiedRegistryPublishers[bare] {
		return true
	}
	// OCI image: require an @sha256: digest pin AND a trusted base.
	if at := strings.Index(bare, "@sha256:"); at > 0 {
		base := bare[:at]
		// Strip a tag if present before the digest (e.g. image:tag@sha256:...).
		if colon := strings.LastIndex(base, ":"); colon > strings.LastIndex(base, "/") {
			base = base[:colon]
		}
		if verifiedOCIImages[base] {
			return true
		}
	}
	return false
}

// isOCIImageArg reports whether an arg looks like an OCI image reference
// (i.e. it starts with a known container registry hostname prefix).
func isOCIImageArg(arg string) bool {
	for _, prefix := range ociRegistryPrefixes {
		if strings.HasPrefix(arg, prefix) {
			return true
		}
	}
	return false
}

// barePackageName strips a registry scheme prefix and version specifier from
// a package name so it can be looked up in verifiedRegistryPublishers or passed
// to isVerifiedProvenance. Handles both "pkg==1.2.3" (Python/uvx style) and
// "pkg@1.2.3" or "@scope/pkg@1.2.3" (npm style).
//
// SF-4 (b): strips leading registry scheme (jsr:, npm:, npx:) so that
// "jsr:@scope/pkg@1.0.0" returns "@scope/pkg" and "npm:mcp-server-git==1.2.3"
// returns "mcp-server-git".
func barePackageName(arg string) string {
	// Strip registry scheme prefix first (SF-4 b).
	arg = stripRegistryScheme(arg)
	if i := strings.Index(arg, "=="); i > 0 {
		return arg[:i]
	}
	// For scoped packages (@scope/pkg@version), the leading @ is part of the
	// name. We must skip the leading @ and find the next @ that begins the
	// version specifier.
	if strings.HasPrefix(arg, "@") {
		// Find the @ that starts the version: it must come after the "/" separator.
		if slash := strings.Index(arg, "/"); slash > 0 {
			if at := strings.Index(arg[slash:], "@"); at > 0 {
				return arg[:slash+at]
			}
		}
		return arg
	}
	// Unscoped package: strip at the first @.
	if i := strings.Index(arg, "@"); i > 0 {
		return arg[:i]
	}
	return arg
}

func (c *mcp006) Run(ctx *model.ScanContext) []model.Finding {
	cfgs := allMCPConfigs(ctx.Collector)
	if len(cfgs) == 0 {
		return []model.Finding{notAssessed("MCP006", "no MCP config files collected")}
	}

	var findings []model.Finding
	for _, cf := range cfgs {
		names := mcpServerNames(cf.Values)
		for _, name := range names {
			cmd := cf.Values[fmt.Sprintf("mcpServers.%s.command", name)]
			containerMode := isContainerRuntime(cmd)

			// Gather all args for this server and look for unverified provenance.
			var suspectArg string
			skipNext := false // SR-3: skip the value arg of a value-carrying flag
			for i := 0; ; i++ {
				key := fmt.Sprintf("mcpServers.%s.args.%d", name, i)
				arg, ok := cf.Values[key]
				if !ok {
					break
				}

				// SF-4 (a): when the command is a container runtime (docker/podman/
				// nerdctl), skip subcommand tokens and flags; only the first non-
				// subcommand/non-flag token is the image reference.
				if containerMode {
					// SR-3: skip the value argument of a value-carrying flag.
					if skipNext {
						skipNext = false
						continue
					}
					if isContainerSubcmdOrFlag(arg) {
						// SR-3: if this flag carries a value, mark the next arg to be skipped.
						if isContainerValueFlag(arg) {
							skipNext = true
						}
						continue
					}
					// This arg is the image reference. Evaluate its provenance.
					if !isVerifiedProvenance(arg) {
						suspectArg = arg
					}
					// Only inspect the first image-like token per container invocation.
					break
				}

				// github: protocol is a direct individual-repo reference — always suspect.
				if strings.HasPrefix(arg, "github:") {
					suspectArg = arg
					break
				}

				// SF-4 (b): strip registry scheme before scope/type detection.
				stripped := stripRegistryScheme(arg)

				// Scoped npm package (@scope/pkg): check verified npm org scopes.
				if strings.HasPrefix(stripped, "@") {
					if !isVerifiedProvenance(arg) {
						suspectArg = arg
						break
					}
					// verified npm scope — keep scanning
					continue
				}
				// OCI image reference (ghcr.io/..., docker.io/..., etc.): must be a
				// pinned-digest image from a trusted registry, otherwise it is suspect.
				if isOCIImageArg(stripped) {
					if !isVerifiedProvenance(arg) {
						suspectArg = arg
						break
					}
					// verified pinned OCI image — keep scanning
					continue
				}
				// Bare (unscoped) package name: check the official registry publisher
				// allowlist after stripping any version specifier.
				// Skip flags, paths, and other non-package tokens.
				if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "/") || arg == "" {
					continue
				}
				bare := barePackageName(arg)
				if !isVerifiedProvenance(bare) {
					// Only flag bare names that look like package names (contain at
					// least one letter and are not a plain version number / flag).
					// This avoids false-positives on numeric args or interpreter flags.
					if bare != arg || strings.ContainsAny(arg, "abcdefghijklmnopqrstuvwxyz") {
						suspectArg = arg
						break
					}
				}
			}
			if suspectArg == "" {
				continue
			}

			f := catalog.Get("MCP006").Finding()
			f.Resource = fmt.Sprintf("mcpServers.%s (%s)", name, cf.Source)
			f.Evidence = fmt.Sprintf("package %q does not appear to come from a verified MCP organization", suspectArg)
			f.ExposureClass = model.ExposureLocalhost
			f.Confidence = model.ConfidenceMedium
			f.Fix = model.Fix{
				Summary: "Prefer MCP servers from verified publishers (e.g. @modelcontextprotocol/*). Review the server source and lock to a specific digest before deploying.",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("MCP006").Pass("All configured MCP servers appear to be from verified publishers.")}
	}
	return findings
}
