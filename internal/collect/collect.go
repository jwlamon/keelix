// Package collect is the inside-out I/O boundary: it gathers host facts and
// returns a *model.Signals. Like internal/probe it is the ONLY place (besides
// probe) that touches the host. Every sub-collector is best-effort: a failure
// appends a model.CollectError and never aborts the whole collection.
package collect

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/jakelamon/keelix/internal/model"
)

// Options controls how Collect operates. Now is injected for deterministic
// tests; when zero it defaults to time.Now().UTC() inside Collect.
type Options struct {
	Privileged bool
	Now        time.Time
	// ServiceConfigs is the list of service-config candidates derived by the
	// engine from parse.Stack. collect reads each via collectConfig with a
	// per-candidate exact-file allowance. The engine populates this; collect
	// stays free of parse/intel imports.
	ServiceConfigs []ConfigCandidate
}

// Collect gathers host signals and returns a non-nil *model.Signals. It never
// panics: each sub-collector's failure is recorded in Signals.Errors. The
// returned error is reserved for catastrophic, non-recoverable setup failures
// (currently none, so it is always nil).
func Collect(opts Options) (*model.Signals, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s := &model.Signals{
		Version:     model.SignalsVersion,
		CollectedAt: now,
		Platform:    model.Platform{OS: runtime.GOOS},
		Privilege:   model.Privilege{EUID: os.Geteuid(), Root: os.Geteuid() == 0},
	}

	// Populate Platform.Distro/Version from /etc/os-release (SP2; best-effort).
	applyOSRelease(&s.Platform, now)

	// Sockets domain.
	sockets, err := collectSockets(opts)
	if err != nil {
		s.Errors = append(s.Errors, model.CollectError{Domain: "sockets", Err: err.Error()})
	} else {
		s.Sockets = sockets
	}

	// Files domain.
	files, err := collectFiles(opts)
	if err != nil {
		s.Errors = append(s.Errors, model.CollectError{Domain: "files", Err: err.Error()})
	} else {
		s.Files = files
	}

	// Processes domain.
	processes, err := collectProcesses()
	if err != nil {
		s.Errors = append(s.Errors, model.CollectError{Domain: "processes", Err: err.Error()})
	} else {
		s.Processes = processes
	}

	// Packages domain.
	packages, err := collectPackages()
	if err != nil {
		s.Errors = append(s.Errors, model.CollectError{Domain: "packages", Err: err.Error()})
	} else {
		s.Packages = packages
	}

	// Firewall domain.
	firewall, err := collectFirewall()
	if err != nil {
		s.Errors = append(s.Errors, model.CollectError{Domain: "firewall", Err: err.Error()})
	} else {
		s.Firewall = firewall
	}

	// SSH domain (SP2: sshd effective configuration).
	sshFact, err := collectSSH(opts)
	if err != nil {
		s.Errors = append(s.Errors, model.CollectError{Domain: "ssh", Err: err.Error()})
	} else if sshFact.SchemaKnown {
		s.Configs = append(s.Configs, sshFact)
	}

	// Docker daemon config (SP3: FW005 signal).
	dockerDaemonFact := collectConfig("/etc/docker/daemon.json", parseDockerDaemon)
	if dockerDaemonFact.SchemaKnown {
		s.Configs = append(s.Configs, dockerDaemonFact)
	}

	// NFS exports (FIX-1: SVC041 reachability — NFS is usually a host service).
	// The containerised path is covered by ServiceConfigCandidates + kindTable.
	nfsFact := collectConfig("/etc/exports", parseNFSExports) // #nosec G304 -- /etc/exports is a pinned allowlisted path
	if nfsFact.SchemaKnown {
		s.Configs = append(s.Configs, nfsFact)
	}

	// Sysctl domain (SP2: kernel hardening parameters, Linux-only).
	sysctlFact, err := collectSysctl()
	if err != nil {
		s.Errors = append(s.Errors, model.CollectError{Domain: "sysctl", Err: err.Error()})
	} else if sysctlFact.SchemaKnown {
		s.Configs = append(s.Configs, sysctlFact)
	}

	// Accounts domain (SP2: passwd, shadow, login.defs, sudoers).
	accountFacts := collectAccountFacts()
	s.Configs = append(s.Configs, accountFacts...)

	// Apt periodic domain (SP2: unattended-upgrades, Linux-only via best-effort).
	aptFacts := collectAptPeriodicFacts()
	s.Configs = append(s.Configs, aptFacts...)

	// Configs domain (AI-agent configuration files).
	configs, err := collectConfigs(opts)
	if err != nil {
		s.Errors = append(s.Errors, model.CollectError{Domain: "configs", Err: err.Error()})
	} else {
		s.Configs = append(s.Configs, configs...)
	}

	// Service-own-config facts (SP3: SVC* checks). Candidates are supplied by the
	// engine via opts.ServiceConfigs; collect reads each through collectConfig.
	svcConfigs := collectServiceConfigs(opts)
	s.Configs = append(s.Configs, svcConfigs...)

	return s, nil
}

// collectServiceConfigs reads each ConfigCandidate from opts.ServiceConfigs
// through the standard collectConfig pipeline (allowlist gate + lstat +
// redaction). Each candidate is granted a one-off exact-file allowlist entry
// scoped to this call; the entry is appended to the package-level allowlist
// only for the duration of the read and removed after.
//
// SAFETY: candidates were produced by ServiceConfigCandidates which enforces
// the bind-mount + expected-basename invariant. collectConfig's own lstat gate
// rejects directories and symlinks as a second-layer defence.
//
// SINGLE-GOROUTINE: Collect (and therefore collectServiceConfigs) must not be
// called concurrently from multiple goroutines — it mutates the package-level
// allowlist slice. The defer-based restore below guarantees the temporary entry
// is removed even if the parser panics, preventing a stale allowlist entry.
func collectServiceConfigs(opts Options) []model.ConfigFact {
	if len(opts.ServiceConfigs) == 0 {
		return nil
	}
	var facts []model.ConfigFact
	for _, c := range opts.ServiceConfigs {
		parser := parserForSchemaID(c.SchemaID)
		if parser == nil {
			// No parser registered for this schema — emit a bare not-yet-known fact.
			facts = append(facts, model.ConfigFact{Source: c.Path, SchemaID: c.SchemaID})
			continue
		}
		// Grant a one-off exact-file allowlist entry for this candidate path,
		// then immediately read it.  A deferred restore ensures the temporary
		// entry is removed even if the parser panics.
		allowlist = append(allowlist, allowEntry{Path: c.Path})
		savedLen := len(allowlist) - 1 // index of the entry we just appended
		fact := func() (f model.ConfigFact) {
			defer func() {
				// Restore the allowlist to its state before the append,
				// regardless of whether the parser returned normally or panicked.
				allowlist = allowlist[:savedLen]
			}()
			return collectConfig(c.Path, parser)
		}()
		if fact.SchemaID == "" {
			fact.SchemaID = c.SchemaID
		}
		facts = append(facts, fact)
	}
	return facts
}

// parserForSchemaID returns the parser function for the given pinned SchemaID,
// or nil if the schema is not yet implemented. Parsers are registered by
// their SchemaID constant; this function is the lookup bridge.
func parserForSchemaID(schemaID string) func([]byte) (map[string]string, string, bool) {
	switch schemaID {
	case "docker-daemon":
		return parseDockerDaemon
	case "redis-conf":
		return parseRedisConf
	case "mongod-conf":
		return parseMongodConf
	case "pg-hba":
		return parsePgHba
	case "elasticsearch-yml":
		return parseElasticsearchYml
	case "arr-config":
		return parseArrConfig
	case "qbittorrent-conf":
		return parseQBittorrentConf
	case "grafana-ini":
		return parseGrafanaIni
	case "prometheus-yml":
		return parsePrometheusYml
	case "vaultwarden-env":
		return parseVaultwardenEnv
	case "vaultwarden-json":
		return parseVaultwardenJSON
	case "gitea-ini":
		return parseGiteaIni
	case "jenkins-config":
		return parseJenkinsConfig
	case "smb-conf":
		return parseSmbConf
	case "nfs-exports":
		return parseNFSExports
	case "minio-env":
		return parseMinioEnv
	case "mosquitto-conf":
		return parseMosquittoConf
	case "syncthing-config":
		return parseSyncthingConfig
	case "traefik-yml":
		return parseTraefikYml
	default:
		return nil
	}
}

// Load reads a Signals JSON document produced by 'keelix collect'.
func Load(path string) (*model.Signals, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied signals file
	if err != nil {
		return nil, fmt.Errorf("read signals %s: %w", path, err)
	}
	var s model.Signals
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse signals %s: %w", path, err)
	}
	return &s, nil
}
