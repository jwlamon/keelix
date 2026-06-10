package collect

import (
	"math"
	"strings"

	"github.com/jakelamon/keelix/internal/model"
)

// secretNameRe matches environment variable names that conventionally hold
// credentials. Matching is case-insensitive and substring-based.
var secretNameTokens = []string{"token", "key", "secret", "password", "passwd", "pwd", "credential", "apikey"}

// classifyEnv categorizes an environment variable WITHOUT ever storing its
// value. The returned EnvShape carries only the name and a coarse class:
// "empty" | "secret" | "path" | "plain".
func classifyEnv(name, value string) model.EnvShape {
	return model.EnvShape{Name: name, Class: classOf(name, value)}
}

// credHeaderKeyNames lists key-name substrings that indicate a credential header
// when used as an environment-variable or dotted-key name (case-insensitive).
var credHeaderKeyNames = []string{"authorization", "x-api-key", "x-auth-token", "api-key", "apikey"}

func classOf(name, value string) string {
	if value == "" {
		return "empty"
	}
	lower := strings.ToLower(name)
	// Secret by key name: conventional secret-bearing variable names.
	for _, tok := range secretNameTokens {
		if strings.Contains(lower, tok) {
			return "secret"
		}
	}
	// Secret by key name: credential header names.
	for _, h := range credHeaderKeyNames {
		if strings.Contains(lower, h) {
			return "secret"
		}
	}
	// Secret by value prefix: Bearer/Basic scheme tokens are credentials even
	// when the token itself has low entropy (e.g. "Bearer abc123").
	lv := strings.ToLower(value)
	if strings.HasPrefix(lv, "bearer ") || strings.HasPrefix(lv, "basic ") {
		return "secret"
	}
	// Network address lists (e.g. docker-daemon "hosts" values like
	// "tcp://0.0.0.0:2375,unix:///var/run/docker.sock") are not secrets even
	// though they have high entropy. Exempt them before the entropy gate.
	if looksLikeNetworkAddrList(value) {
		return "plain"
	}
	// Secret by high entropy.
	if shannonEntropy(value) >= 4.0 && len(value) >= 20 {
		return "secret"
	}
	if looksLikePath(value) {
		return "path"
	}
	return "plain"
}

// looksLikeNetworkAddrList reports whether value is a comma-separated list of
// docker-daemon transport addresses (tcp:// or unix:// only) without embedded
// userinfo credentials (user:pass@host). This prevents the entropy-based
// secret classifier from masking legitimate docker daemon host lists such as
// "tcp://0.0.0.0:2375,unix:///var/run/docker.sock".
//
// Intentionally excludes http://, https://, and udp:// so that high-entropy
// webhook tokens (e.g. https://hooks.example.com/services/T.../B.../secret)
// under non-credential key names are still caught by the entropy gate.
func looksLikeNetworkAddrList(value string) bool {
	if value == "" {
		return false
	}
	// Split on commas; every element must be a tcp:// or unix:// address.
	// http://, https://, and udp:// are intentionally excluded — they can carry
	// high-entropy secrets (webhook URLs) and must not bypass the entropy gate.
	netSchemes := []string{"tcp://", "unix://"}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		matched := false
		for _, scheme := range netSchemes {
			if strings.HasPrefix(strings.ToLower(part), scheme) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
		// Reject if userinfo credentials are embedded (user:pass@host).
		if hasURLUserinfo(part) {
			return false
		}
	}
	return true
}

// looksLikePath reports whether value resembles a filesystem path.
func looksLikePath(value string) bool {
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "~/") {
		return true
	}
	return false
}

// shannonEntropy returns the Shannon entropy (bits per symbol) of s.
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
