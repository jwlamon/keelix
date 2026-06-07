package collect

import (
	"strings"
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestServiceConfigCandidates_BindMount(t *testing.T) {
	stack := &model.Stack{
		Services: []*model.Service{
			{
				Name:  "redis",
				Image: "redis:7",
				Volumes: []model.VolumeMount{
					{Type: "bind", Source: "/srv/redis", Target: "/data"},
					{Type: "bind", Source: "/srv/redis/redis.conf", Target: "/usr/local/etc/redis/redis.conf"},
				},
			},
		},
	}
	candidates := ServiceConfigCandidates(stack)
	found := false
	for _, c := range candidates {
		if c.Path == "/srv/redis/redis.conf" && c.SchemaID == "redis-conf" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected candidate {/srv/redis/redis.conf, redis-conf}; got %+v", candidates)
	}
}

func TestServiceConfigCandidates_NamedVolume_Excluded(t *testing.T) {
	stack := &model.Stack{
		Services: []*model.Service{
			{
				Name:  "mongo",
				Image: "mongo:7",
				Volumes: []model.VolumeMount{
					{Type: "volume", Source: "mongo_data", Target: "/data/db"},
				},
			},
		},
	}
	candidates := ServiceConfigCandidates(stack)
	for _, c := range candidates {
		if c.SchemaID == "mongod-conf" {
			t.Errorf("named volume must not produce a candidate; got %+v", c)
		}
	}
}

func TestServiceConfigCandidates_BasenameGate(t *testing.T) {
	// A bind-mount directory (not a file) must not produce a candidate directly.
	// Only an exact-file source whose basename is in the expected set passes.
	stack := &model.Stack{
		Services: []*model.Service{
			{
				Name:  "redis",
				Image: "redis:7",
				Volumes: []model.VolumeMount{
					// Source is a directory, not a file matching the expected basename.
					{Type: "bind", Source: "/srv/redis-data", Target: "/data"},
				},
			},
		},
	}
	candidates := ServiceConfigCandidates(stack)
	for _, c := range candidates {
		if c.SchemaID == "redis-conf" {
			t.Errorf("directory source must not produce redis-conf candidate; got %+v", c)
		}
	}
}

// TestServiceConfigCandidates_KindSpecCollision verifies R3-5: when two kindSpecs
// both match an image (e.g. an image name containing "arr" and "jenkins") and
// both claim the same expectedBasename (config.xml), only the most-specific
// (longest keyword) match should be emitted — not both.
func TestServiceConfigCandidates_KindSpecCollision(t *testing.T) {
	// "linuxserver/sonarr-jenkins" contains both "sonarr" (6 chars) and "jenkins" (7 chars).
	// The longer keyword "jenkins" wins → schemaID "jenkins-config".
	// Only ONE candidate for config.xml should appear.
	stack := &model.Stack{
		Services: []*model.Service{
			{
				Name:  "weird",
				Image: "linuxserver/sonarr-jenkins:latest",
				Volumes: []model.VolumeMount{
					{Type: "bind", Source: "/srv/app/config.xml", Target: "/config/config.xml"},
				},
			},
		},
	}
	candidates := ServiceConfigCandidates(stack)
	// Count how many times config.xml appears as a candidate.
	count := 0
	for _, c := range candidates {
		if c.Path == "/srv/app/config.xml" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 candidate for config.xml collision, got %d: %+v", count, candidates)
	}
	// Verify the winner is jenkins (longest keyword).
	for _, c := range candidates {
		if c.Path == "/srv/app/config.xml" && c.SchemaID != "jenkins-config" {
			t.Errorf("expected winner schemaID=jenkins-config (longer keyword), got %q", c.SchemaID)
		}
	}
}

func TestDockerDaemonPipeline_TCPEntry(t *testing.T) {
	fact := collectConfigInternal(
		"testdata/docker_daemon_tcp.json",
		parseDockerDaemon,
	)
	if !fact.SchemaKnown {
		t.Fatal("want SchemaKnown=true")
	}
	if fact.SchemaID != "docker-daemon" {
		t.Fatalf("SchemaID = %q, want %q", fact.SchemaID, "docker-daemon")
	}
	hosts, ok := fact.Values["hosts"]
	if !ok {
		t.Fatal("Values missing key 'hosts'")
	}
	if !strings.Contains(hosts, "tcp://0.0.0.0:2375") {
		t.Fatalf("Values[hosts] = %q, want tcp://0.0.0.0:2375 present", hosts)
	}
}

func TestDockerDaemonPipeline_LoopbackOnly(t *testing.T) {
	fact := collectConfigInternal(
		"testdata/docker_daemon_loopback.json",
		parseDockerDaemon,
	)
	if !fact.SchemaKnown {
		t.Fatal("want SchemaKnown=true")
	}
	hosts := fact.Values["hosts"]
	if !strings.Contains(hosts, "tcp://127.0.0.1") {
		t.Fatalf("Values[hosts] = %q, want loopback entry", hosts)
	}
}
