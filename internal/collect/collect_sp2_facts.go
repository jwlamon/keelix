package collect

import (
	"bytes"
	"os"
	"path/filepath"
	"time"

	"github.com/jwlamon/keelix/internal/model"
)

// collectAccountFacts reads /etc/passwd, /etc/shadow, /etc/login.defs,
// /etc/sudoers, and all /etc/sudoers.d/* fragments via the allowlist-gated
// collectConfig framework. Each is best-effort; missing files produce bare
// facts (SchemaKnown=false). On macOS these paths do not exist and all facts
// will have SchemaKnown=false, which is correct (the HST checks will return
// NotAssessed for darwin).
//
// /etc/sudoers.d fragments are merged into a single ConfigFact so that checks
// see a unified view: NOPASSWD rules split across drop-in files are detected
// the same way as rules in the main sudoers file.
func collectAccountFacts() []model.ConfigFact {
	facts := []model.ConfigFact{
		collectConfig("/etc/passwd", parsePasswd),
		collectConfig("/etc/shadow", parseShadow),
		collectConfig("/etc/login.defs", parseLoginDefs),
		collectConfig("/etc/sudoers", parseSudoers),
	}

	// Merge /etc/sudoers.d/* fragments into a single additional ConfigFact.
	// The allowlist already includes the prefix "/etc/sudoers.d", so each
	// fragment path passes the isAllowed gate inside collectConfig.
	if merged := collectSudoersDFacts(); merged.SchemaKnown {
		facts = append(facts, merged)
	}
	return facts
}

// collectSudoersDFacts enumerates /etc/sudoers.d/*, reads each non-directory,
// non-symlink fragment through the allowlist-gated collectConfig path, and
// concatenates the raw bytes before running parseSudoers over the combined
// content. Returns a bare ConfigFact (SchemaKnown=false) when the directory is
// absent, unreadable, or contains no allowlist-permitted readable files.
//
// Using collectConfig per fragment enforces the same allowlist and symlink
// refusal rules as every other config reader in the collector.
func collectSudoersDFacts() model.ConfigFact {
	const dir = "/etc/sudoers.d"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return model.ConfigFact{Source: dir}
	}

	var combined bytes.Buffer
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		fragPath := filepath.Join(dir, de.Name())
		// Use collectConfig to honour the allowlist gate and symlink refusal.
		// The closure accumulates raw bytes; returning known=false signals that
		// this intermediate fact should not be stored on its own.
		collectConfig(fragPath, func(b []byte) (map[string]string, string, bool) {
			combined.Write(b)
			combined.WriteByte('\n')
			return nil, "", false
		})
	}

	if combined.Len() == 0 {
		return model.ConfigFact{Source: dir}
	}

	// parseSudoers already redacts command paths; no further redaction is needed.
	vals, schemaID, known := parseSudoers(combined.Bytes())
	return model.ConfigFact{
		Source:      dir,
		SchemaID:    schemaID,
		SchemaKnown: known,
		Values:      vals,
	}
}

// collectAptPeriodicFacts reads the two standard apt periodic config files.
// Missing files produce bare facts (SchemaKnown=false) — this is the correct
// posture for non-Debian systems and macOS.
func collectAptPeriodicFacts() []model.ConfigFact {
	return []model.ConfigFact{
		collectConfig("/etc/apt/apt.conf.d/20auto-upgrades", parseAptPeriodic),
		collectConfig("/etc/apt/apt.conf.d/50unattended-upgrades", parseAptPeriodic),
	}
}

// applyOSRelease reads /etc/os-release and populates p.Distro and p.Version.
// It also returns the eol flag so the caller can set Packages.DistroEOL when
// the packages collector could not determine it (e.g. on non-apt systems).
// Returns silently if /etc/os-release is absent or unreadable.
func applyOSRelease(p *model.Platform, collectedAt time.Time) bool {
	b, err := os.ReadFile("/etc/os-release") // #nosec G304 -- fixed path
	if err != nil {
		return false
	}
	distro, version, eol := parseOSRelease(b, collectedAt)
	p.Distro = distro
	p.Version = version
	return eol
}
