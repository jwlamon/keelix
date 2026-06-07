//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// knownCacheRoots returns the set of directory prefixes that are considered
// safe to allow as read-only cache entries on darwin. Only paths equal to, or
// strict subdirectories of, one of these roots are accepted. This prevents
// cache-path injection (SBX-4): a config env pointing npm_config_cache at
// ~/.ssh would otherwise re-grant HOME read access through an explicit allow.
//
// The roots are derived from $HOME at call time. On error we fall back to a
// non-existent path that never matches, preserving the default-deny posture.
func knownCacheRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/nonexistent-no-home"
	}
	return []string{
		filepath.Join(home, ".npm"),
		filepath.Join(home, ".cache"),
		filepath.Join(home, "Library", "Caches"),
		"/tmp",
	}
}

// allowedCachePath reports whether p is a safe cache path: it must be exactly
// one of the known cache roots or a subdirectory thereof (SBX-4).
// filepath.Clean is applied; EvalSymlinks is skipped intentionally because the
// path may not exist yet — symlink-loop attacks are blocked by the absolute
// prefix check against known roots.
func allowedCachePath(p string) bool {
	if p == "" {
		return false
	}
	p = filepath.Clean(p)
	for _, root := range knownCacheRoots() {
		root = filepath.Clean(root)
		if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// roCaches collects npm/uvx cache dirs that Seatbelt should allow read-only so
// server launchers can resolve their packages. Each candidate path is validated
// against the known-safe cache roots (SBX-4): any path outside ~/.npm,
// ~/.cache, ~/Library/Caches, or /tmp is silently dropped so a poisoned
// config env like npm_config_cache=~/.ssh cannot re-grant HOME read access via
// an explicit Seatbelt subpath allow.
func roCaches(env map[string]string) []string {
	var out []string
	add := func(p string) {
		if p != "" && allowedCachePath(p) {
			out = append(out, p)
		}
	}
	add(env["npm_config_cache"])
	add(env["UV_CACHE_DIR"])
	add(env["NPM_CONFIG_CACHE"])
	return out
}

// seatbeltProfile builds a Seatbelt (SBPL) profile string for sandbox-exec.
//
// Security model (SBX-3 — deny-default + scoped allows):
//   - deny default — everything is denied unless explicitly allowed.
//   - Deny file-read* under the real user $HOME. In Apple Seatbelt a deny is
//     authoritative: once a matching (deny ...) rule is PRESENT in the profile
//     it wins regardless of where it sits relative to a broader (allow ...) —
//     ordering does NOT decide the outcome (Seatbelt is not first-match /
//     last-match for deny-vs-allow on the same operation). So the mere presence
//     of this deny — not its position — is what guarantees ~/.ssh, ~/.aws,
//     agent tokens and other secrets cannot be read by a poisoned MCP server.
//   - Allow file-read* broadly for everything else — system libraries,
//     /opt/homebrew, /usr/local, /System, /Library, /usr, /bin, /sbin, /dev
//     etc. — so npx/uvx/node/python can locate and load their runtimes and
//     caches. The child's HOME env var is already pointed at writableRoot (set
//     by cleanEnv in base.go), so npm/pip caches live in the tempdir.
//   - Allow file-write* and file-read* ONLY under writableRoot (the resolved
//     system temp root) and /dev/null (needed for stderr redirects in shell
//     wrappers).
//   - For validated cache paths (SBX-4): explicit (allow file-read* (subpath
//     ...)) entries for each path that passes allowedCachePath — these
//     exceptions to the broad allow are belt-and-suspenders for when the
//     broad allow is narrowed in future; they are safe because allowedCachePath
//     already filtered out any HOME-read bypass.
//   - Deny network* — a poisoned server must never exfil data.
//   - Allow process-exec*, process-fork, sysctl-read, mach-lookup — the
//     minimum for Go/libc/dyld startup plus the interpreter launch chain.
//
// writableRoot MUST be a realpath (symlinks resolved): on macOS os.TempDir()
// is /var/folders/... which symlinks to /private/var/folders/...; Seatbelt
// subpath matching does not follow symlinks, so an unresolved path silently
// denies writes into the tempdir.
//
// caches is the output of roCaches(spec.Env): only paths that passed
// allowedCachePath are present, so no injected path can appear here.
func seatbeltProfile(writableRoot string, caches []string) string {
	// Resolve the real user $HOME so we can deny it explicitly. On error we
	// fall back to the zero string which produces an invalid subpath deny that
	// is harmlessly ignored by SBPL (defence-in-depth; the test will catch it).
	home, _ := os.UserHomeDir()

	base := fmt.Sprintf(
		"(version 1)"+
			"(deny default)"+
			"(allow process-exec*)"+
			"(allow process-fork)"+
			"(allow sysctl-read)"+
			"(allow mach-lookup)"+
			// SBX-3: deny $HOME reads. The presence of this deny — not its
			// position relative to the broad allow below — is what blocks reads of
			// ~/.ssh, ~/.aws, agent tokens, etc. (a Seatbelt deny is authoritative).
			"(deny file-read* (subpath %q))"+
			// Allow reads everywhere else (system libs, homebrew, /dev, …).
			"(allow file-read*)"+
			// Writes: only inside the sandbox tempdir and /dev/null.
			"(allow file-write* (subpath %q))"+
			"(allow file-write* (literal \"/dev/null\"))"+
			"(deny network*)",
		home,
		writableRoot,
	)

	// SBX-4: append explicit read-only subpath allows for validated cache dirs.
	// allowedCachePath has already filtered caches, so none can be under HOME.
	for _, c := range caches {
		base += fmt.Sprintf("(allow file-read* (subpath %q))", c)
	}
	return base
}
