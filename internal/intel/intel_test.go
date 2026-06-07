package intel

import "testing"

func TestImageBase(t *testing.T) {
	cases := map[string]string{
		"postgres:16":                              "postgres",
		"postgres":                                 "postgres",
		"grafana/grafana:10.2.0":                   "grafana/grafana",
		"docker.io/grafana/grafana:latest":         "grafana/grafana",
		"ghcr.io/foo/bar@sha256:abc":               "foo/bar",
		"registry.example.com:5000/team/app:1.2.3": "team/app",
		"redis:7@sha256:deadbeef":                  "redis",
		// SF-2: official Docker Hub images use library/ namespace — must be stripped.
		"docker.io/library/solr:8.11":          "solr",
		"docker.io/library/redis:7":            "redis",
		"index.docker.io/library/nginx:latest": "nginx",
		"registry-1.docker.io/library/alpine":  "alpine",
		"library/redis":                        "redis",
		"solr":                                 "solr",
		"ghcr.io/foo/bar":                      "foo/bar", // non-library path unchanged
		// SR-2: library/ strip must be Docker Hub ONLY — private registries keep the path.
		"ghcr.io/library/foo":       "library/foo",
		"myreg.io/library/bar":      "library/bar",
		"myregistry.io/library/foo": "library/foo",
	}
	for in, want := range cases {
		if got := ImageBase(in); got != want {
			t.Errorf("ImageBase(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestImageCVEsOfficialImages verifies that every images_cve.go entry for a
// well-known official image resolves via its canonical docker.io/library/<key>
// form. This catches regressions of the library/ stripping fix.
func TestImageCVEsOfficialImages(t *testing.T) {
	officialKeys := []string{"solr", "elasticsearch"}
	for _, key := range officialKeys {
		canonical := "docker.io/library/" + key + ":latest"
		if _, ok := ImageCVEs(canonical); !ok {
			t.Errorf("ImageCVEs(%q): official image key %q not reachable via canonical form", canonical, key)
		}
	}
}

func TestImageTagAndDigest(t *testing.T) {
	if ImageTag("redis:7") != "7" {
		t.Error("tag redis:7")
	}
	if ImageTag("redis") != "" {
		t.Error("no tag")
	}
	if ImageTag("registry.example.com:5000/app") != "" {
		t.Error("registry port must not be read as tag")
	}
	if !HasDigest("redis@sha256:abc") {
		t.Error("digest detection")
	}
	if HasDigest("redis:7") {
		t.Error("false digest")
	}
}

func TestSensitivePort(t *testing.T) {
	if !IsSensitivePort(5432) {
		t.Error("5432 should be sensitive")
	}
	if p, _ := LookupPort(6379); p.Service != "Redis" {
		t.Errorf("6379 = %q", p.Service)
	}
}

func TestWeakPassword(t *testing.T) {
	for _, w := range []string{"", "admin", "changeme", "short", "postgres", "123456"} {
		if !IsWeakPassword(w) {
			t.Errorf("%q should be weak", w)
		}
	}
	if IsWeakPassword("c0rrect-h0rse-battery-staple") {
		t.Error("strong password flagged weak")
	}
}

func TestDefaultCredentials(t *testing.T) {
	if _, ok := DefaultCredentials("grafana/grafana:10"); !ok {
		t.Error("grafana defaults should be known")
	}
	if _, ok := DefaultCredentials("my/unknown-app"); ok {
		t.Error("unknown image should have no defaults")
	}
}

func TestSecretEnvName(t *testing.T) {
	for _, n := range []string{"POSTGRES_PASSWORD", "API_KEY", "JWT_SECRET", "DB_DSN"} {
		if !IsSecretEnvName(n) {
			t.Errorf("%q should look secret", n)
		}
	}
	if IsSecretEnvName("LOG_LEVEL") {
		t.Error("LOG_LEVEL is not a secret")
	}
}

func TestDangerousCap(t *testing.T) {
	if _, ok := DangerousCap("SYS_ADMIN"); !ok {
		t.Error("SYS_ADMIN dangerous")
	}
	if _, ok := DangerousCap("CAP_NET_ADMIN"); !ok {
		t.Error("CAP_ prefix should be stripped")
	}
	if _, ok := DangerousCap("CHOWN"); ok {
		t.Error("CHOWN is benign")
	}
}

func TestExpectedPublicPort(t *testing.T) {
	if !ExpectedPublicPort("jellyfin/jellyfin", 8096) {
		t.Error("jellyfin 8096 expected public")
	}
	if ExpectedPublicPort("postgres:16", 5432) {
		t.Error("postgres 5432 is not an expected public port")
	}
	if !ExpectedPublicPort("anything", 443) {
		t.Error("443 generally public")
	}
}
