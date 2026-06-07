package intel

import "strings"

// Credential is a documented default credential for a well-known image.
type Credential struct {
	Username string
	Password string
	Note     string
}

// dockerHubHosts is the set of registry hostnames that implement the Docker Hub
// implicit official-image "library/" namespace convention. Only for these hosts
// (and bare image references with no host) should a leading "library/" segment
// be stripped so that "docker.io/library/solr" resolves to the bare key "solr"
// used in imageCVEs.
var dockerHubHosts = map[string]bool{
	"docker.io":            true,
	"index.docker.io":      true,
	"registry-1.docker.io": true,
}

// ImageBase strips the registry, tag and digest from an image reference,
// returning e.g. "grafana/grafana" from "docker.io/grafana/grafana:10.2@sha256:..".
func ImageBase(image string) string {
	s := image
	// Drop digest.
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	// Drop tag (the last colon that is not part of a registry:port host). We
	// only strip a tag if the colon appears after the last slash.
	if slash := strings.LastIndex(s, "/"); slash >= 0 {
		if colon := strings.LastIndex(s, ":"); colon > slash {
			s = s[:colon]
		}
	} else if colon := strings.LastIndex(s, ":"); colon >= 0 {
		s = s[:colon]
	}
	// Drop a leading registry host (contains a dot or a port, or is localhost).
	// Track whether the host was a recognised Docker Hub host so we can apply
	// the library/ strip only for Docker Hub references.
	isDockerHub := false
	if slash := strings.Index(s, "/"); slash >= 0 {
		host := s[:slash]
		if strings.ContainsAny(host, ".:") || host == "localhost" {
			if dockerHubHosts[host] {
				isDockerHub = true
			}
			s = s[slash+1:]
		} else {
			// No registry host detected — bare image reference like "library/redis"
			// or "grafana/grafana". Docker Hub is the default registry for these.
			isDockerHub = true
		}
	} else {
		// Single component with no slash — definitely Docker Hub (e.g. "solr", "redis").
		isDockerHub = true
	}
	// Strip the implicit Docker Hub official-image namespace so that
	// "library/solr" (produced from "docker.io/library/solr:8.11") resolves
	// to "solr" — the bare key used in imageCVEs. This strip applies ONLY for
	// Docker Hub references; private registries like ghcr.io or myreg.io may
	// legitimately have a "library" path component with a different meaning.
	if isDockerHub {
		s = strings.TrimPrefix(s, "library/")
	}
	return strings.ToLower(s)
}

// ImageTag returns the tag portion of an image reference, or "" if none.
func ImageTag(image string) string {
	s := image
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	slash := strings.LastIndex(s, "/")
	colon := strings.LastIndex(s, ":")
	if colon > slash {
		return s[colon+1:]
	}
	return ""
}

// HasDigest reports whether the image reference is pinned to a content digest.
func HasDigest(image string) bool {
	return strings.Contains(image, "@sha256:")
}

// defaultCredentials maps an image base name to its documented default
// credentials. Keys are matched as substrings of the normalized image base.
var defaultCredentials = map[string][]Credential{
	"grafana/grafana":              {{"admin", "admin", "Grafana ships with admin/admin"}},
	"portainer/portainer":          {{"admin", "", "Set on first login; default is unauthenticated until set"}},
	"jc21/nginx-proxy-manager":     {{"admin@example.com", "changeme", "Nginx Proxy Manager default"}},
	"nginxproxymanager":            {{"admin@example.com", "changeme", "Nginx Proxy Manager default"}},
	"gitea/gitea":                  {{"", "", "First-run installer can be left open — lock it down"}},
	"sonarqube":                    {{"admin", "admin", "SonarQube default"}},
	"pihole/pihole":                {{"admin", "", "Web password set via WEBPASSWORD"}},
	"minio/minio":                  {{"minioadmin", "minioadmin", "MinIO default root credentials"}},
	"rabbitmq":                     {{"guest", "guest", "RabbitMQ default (localhost only by default)"}},
	"elastic/kibana":               {{"elastic", "changeme", "Elastic default"}},
	"kibana":                       {{"elastic", "changeme", "Elastic default"}},
	"mongo-express":                {{"admin", "pass", "mongo-express default basic auth"}},
	"phpmyadmin":                   {{"root", "", "phpMyAdmin uses the DB credentials"}},
	"adminer":                      {{"", "", "Adminer exposes DB login directly"}},
	"keycloak":                     {{"admin", "admin", "Keycloak bootstrap admin"}},
	"jenkins/jenkins":              {{"admin", "", "Initial admin password in container logs"}},
	"homeassistant/home-assistant": {{"", "", "Onboarding sets credentials — do not expose before setup"}},
}

// DefaultCredentials returns documented default credentials for an image, if known.
func DefaultCredentials(image string) ([]Credential, bool) {
	base := ImageBase(image)
	for key, creds := range defaultCredentials {
		if strings.Contains(base, key) {
			return creds, true
		}
	}
	return nil, false
}

// weakPasswords is a set of common weak/default passwords.
var weakPasswords = map[string]bool{
	"password": true, "passwd": true, "admin": true, "administrator": true,
	"root": true, "toor": true, "changeme": true, "change-me": true,
	"123456": true, "12345678": true, "123456789": true, "qwerty": true,
	"letmein": true, "secret": true, "default": true, "test": true,
	"postgres": true, "mysql": true, "redis": true, "mongo": true,
	"guest": true, "demo": true, "example": true, "password1": true,
	"abc123": true, "p@ssw0rd": true, "welcome": true, "admin123": true,
	"": true,
}

// IsWeakPassword reports whether the password is empty, very short, or a known
// common/default password.
func IsWeakPassword(pw string) bool {
	if len(pw) < 8 {
		return true
	}
	return weakPasswords[strings.ToLower(strings.TrimSpace(pw))]
}

// secretEnvKeywords are substrings in an environment variable name that indicate
// the value is a secret.
var secretEnvKeywords = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"private_key", "privatekey", "access_key", "accesskey", "credential",
	"_key", "auth", "jwt", "session_secret", "encryption", "dsn",
}

// IsSecretEnvName reports whether an env var name looks like it holds a secret.
func IsSecretEnvName(name string) bool {
	n := strings.ToLower(name)
	for _, kw := range secretEnvKeywords {
		if strings.Contains(n, kw) {
			return true
		}
	}
	return false
}

// dangerousCaps are Linux capabilities that materially widen container risk.
var dangerousCaps = map[string]string{
	"ALL":             "grants every capability",
	"SYS_ADMIN":       "near-root: mount, namespaces, many escapes",
	"NET_ADMIN":       "reconfigure host networking",
	"SYS_PTRACE":      "inspect/modify other processes",
	"SYS_MODULE":      "load kernel modules (full host compromise)",
	"DAC_READ_SEARCH": "bypass file read permission checks",
	"SYS_RAWIO":       "raw I/O port access",
	"SYS_BOOT":        "reboot the host",
	"BPF":             "load eBPF programs",
}

// DangerousCap returns a reason if the capability is dangerous.
func DangerousCap(cap string) (string, bool) {
	reason, ok := dangerousCaps[strings.ToUpper(strings.TrimPrefix(strings.ToUpper(cap), "CAP_"))]
	return reason, ok
}
