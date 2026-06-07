package redact

import (
	"math"
	"regexp"
	"strings"

	"github.com/jwlamon/keelix/internal/intel"
	"github.com/jwlamon/keelix/internal/model"
)

// marker is what replaces a secret span.
const marker = "[REDACTED]"

// minKnownValueLen is the shortest known .env value we will redact as a
// substring; shorter values cause noisy false positives in ordinary prose.
const minKnownValueLen = 6

// entropyThreshold is the Shannon entropy (bits/char) at/above which a long
// alphanumeric token is treated as a high-entropy secret.
const entropyThreshold = 3.5

// minTokenLen is the shortest standalone token considered for the high-entropy
// rule.
const minTokenLen = 24

var (
	// scheme://user:password@host  -> capture the password segment.
	reConnString = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:)([^\s@/]+)(@)`)
	// Bearer <token>
	reBearer = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9._\-+/=]+)`)
	// JWT: three base64url segments, header begins eyJ.
	reJWT = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`)
	// Candidate standalone high-entropy token.
	reToken = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{` + itoa(minTokenLen) + `,}`)
)

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// redactor holds the precomputed set of known secret values for one scan.
type redactor struct {
	known []string // distinct, length-sorted desc, each >= minKnownValueLen
}

// newRedactor builds a redactor from raw known values (typically .env values
// whose keys looked like secrets). Values shorter than minKnownValueLen are
// dropped. Longer values are sorted longest-first so overlapping values redact
// the most specific match.
func newRedactor(known []string) *redactor {
	seen := map[string]struct{}{}
	var out []string
	for _, k := range known {
		k = strings.TrimSpace(k)
		if len(k) < minKnownValueLen {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	// Longest first.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if len(out[j]) > len(out[i]) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return &redactor{known: out}
}

// redactString applies all redaction rules to s, in priority order.
func (r *redactor) redactString(s string) string {
	if s == "" {
		return s
	}
	// 1. Known values (exact substrings).
	for _, k := range r.known {
		if strings.Contains(s, k) {
			s = strings.ReplaceAll(s, k, marker)
		}
	}
	// 2. Connection-string passwords.
	s = reConnString.ReplaceAllString(s, "${1}"+marker+"${3}")
	// 3. Bearer tokens.
	s = reBearer.ReplaceAllString(s, "${1}"+marker)
	// 4. JWTs.
	s = reJWT.ReplaceAllString(s, marker)
	// 5. High-entropy standalone tokens.
	s = reToken.ReplaceAllStringFunc(s, func(tok string) string {
		if tok == marker {
			return tok
		}
		if shannonEntropy(tok) >= entropyThreshold {
			return marker
		}
		return tok
	})
	return s
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// knownSecretValues collects the .env values whose keys look like secrets, so
// the redactor can replace those exact byte sequences wherever they appear.
func knownSecretValues(s *model.Stack) []string {
	if s == nil {
		return nil
	}
	var out []string
	for k, v := range s.Env {
		if intel.IsSecretEnvName(k) {
			out = append(out, v)
		}
	}
	return out
}

// redactFinding scrubs every free-text field of a single finding in place,
// including the inside-out v2 fields (Mitigations).
func (r *redactor) redactFinding(f *model.Finding) {
	f.Title = r.redactString(f.Title)
	f.Detail = r.redactString(f.Detail)
	f.Evidence = r.redactString(f.Evidence)
	f.Resource = r.redactString(f.Resource)
	f.Fix.Summary = r.redactString(f.Fix.Summary)
	f.Fix.Diff = r.redactString(f.Fix.Diff)
	for j := range f.Fix.Commands {
		f.Fix.Commands[j] = r.redactString(f.Fix.Commands[j])
	}
	for j := range f.Mitigations {
		f.Mitigations[j] = r.redactString(f.Mitigations[j])
	}
	if f.Metadata != nil {
		for k, v := range f.Metadata {
			f.Metadata[k] = r.redactString(v)
		}
	}
}

// Result redacts every secret-bearing free-text field of r in place, per the
// package spec. It is nil-safe and runs unconditionally; it never errors.
func Result(r *model.Result) {
	if r == nil {
		return
	}
	red := newRedactor(knownSecretValues(r.Stack))

	r.AISummary = red.redactString(r.AISummary)

	for i := range r.Findings {
		red.redactFinding(&r.Findings[i])
	}
	for i := range r.NotAssessed {
		red.redactFinding(&r.NotAssessed[i])
	}

	if r.CapDriver != nil {
		r.CapDriver.Reason = red.redactString(r.CapDriver.Reason)
	}

	if r.Probe != nil {
		for port, pp := range r.Probe.Reachable {
			if pp.Banner != "" {
				pp.Banner = red.redactString(pp.Banner)
				r.Probe.Reachable[port] = pp
			}
		}
	}

	if r.Collector != nil {
		// Scrub ConfigFact.Values (may contain raw config values including secrets).
		for i := range r.Collector.Configs {
			for k, v := range r.Collector.Configs[i].Values {
				r.Collector.Configs[i].Values[k] = red.redactString(v)
			}
		}
		// Scrub Firewall.Rules (free-text rule entries may embed tokens).
		for i, rule := range r.Collector.Firewall.Rules {
			r.Collector.Firewall.Rules[i] = red.redactString(rule)
		}
		// Scrub ProcessFact.Args (command-line args may contain --key=secret).
		for i := range r.Collector.Processes {
			for j, arg := range r.Collector.Processes[i].Args {
				r.Collector.Processes[i].Args[j] = red.redactString(arg)
			}
		}
		// Scrub CollectError.Err (error messages may reflect secret values).
		for i := range r.Collector.Errors {
			r.Collector.Errors[i].Err = red.redactString(r.Collector.Errors[i].Err)
		}
		// Scrub MCPProbe free-text (server names, tool names, error strings).
		// A malicious tool name or error fragment can carry a secret token out of
		// the sandbox into the report — redact unconditionally (SBX-9a).
		if r.Collector.MCPProbe != nil {
			for i := range r.Collector.MCPProbe.Servers {
				srv := &r.Collector.MCPProbe.Servers[i]
				srv.Name = red.redactString(srv.Name)
				for j := range srv.Errors {
					srv.Errors[j] = red.redactString(srv.Errors[j])
				}
				for j := range srv.Tools {
					srv.Tools[j].Name = red.redactString(srv.Tools[j].Name)
				}
			}
		}
	}
}
