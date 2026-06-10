package collect

import (
	"path/filepath"

	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

// ConfigCandidate is one discovered service-config file candidate.
type ConfigCandidate struct {
	// Path is the absolute host-side path of the config file.
	Path string
	// SchemaID is the pinned schema identifier for this config kind.
	SchemaID string
	// Kind is the service kind string (for diagnostics/logging).
	Kind string
}

// kindSpec describes the expected file for one service kind.
type kindSpec struct {
	// imageKeywords are substrings matched against intel.ImageBase(image).
	imageKeywords []string
	// schemaID is the PINNED SchemaID the parser for this kind emits.
	schemaID string
	// expectedBasenames is the allowed set of config-file basenames for this kind.
	// A compose-derived source path is accepted ONLY when its basename is in this set.
	expectedBasenames []string
}

// kindTable is the curated table of service kinds Keelix can discover and assess.
// SAFETY: a bind-mount source path is read only when its basename is in
// expectedBasenames AND os.Lstat confirms it is a regular file (not a dir/symlink).
var kindTable = []kindSpec{
	{
		imageKeywords:     []string{"redis"},
		schemaID:          "redis-conf",
		expectedBasenames: []string{"redis.conf"},
	},
	{
		imageKeywords:     []string{"mongo"},
		schemaID:          "mongod-conf",
		expectedBasenames: []string{"mongod.conf", "mongod.yml", "mongod.yaml"},
	},
	{
		imageKeywords:     []string{"postgres", "postgresql"},
		schemaID:          "pg-hba",
		expectedBasenames: []string{"pg_hba.conf"},
	},
	{
		imageKeywords:     []string{"elasticsearch"},
		schemaID:          "elasticsearch-yml",
		expectedBasenames: []string{"elasticsearch.yml", "elasticsearch.yaml"},
	},
	{
		imageKeywords:     []string{"sonarr", "radarr", "prowlarr", "lidarr", "readarr"},
		schemaID:          "arr-config",
		expectedBasenames: []string{"config.xml"},
	},
	{
		imageKeywords:     []string{"qbittorrent", "linuxserver/qbittorrent"},
		schemaID:          "qbittorrent-conf",
		expectedBasenames: []string{"qBittorrent.conf"},
	},
	{
		imageKeywords:     []string{"grafana"},
		schemaID:          "grafana-ini",
		expectedBasenames: []string{"grafana.ini"},
	},
	{
		imageKeywords:     []string{"prometheus"},
		schemaID:          "prometheus-yml",
		expectedBasenames: []string{"prometheus.yml", "prometheus.yaml"},
	},
	{
		imageKeywords:     []string{"vaultwarden"},
		schemaID:          "vaultwarden-env",
		expectedBasenames: []string{".env"},
	},
	// vaultwarden-json: Vaultwarden's admin-panel config.json (JSON format).
	// Separate from vaultwarden-env because the file format is entirely different.
	{
		imageKeywords:     []string{"vaultwarden"},
		schemaID:          "vaultwarden-json",
		expectedBasenames: []string{"config.json"},
	},
	{
		imageKeywords:     []string{"gitea"},
		schemaID:          "gitea-ini",
		expectedBasenames: []string{"app.ini"},
	},
	{
		imageKeywords:     []string{"jenkins"},
		schemaID:          "jenkins-config",
		expectedBasenames: []string{"config.xml"},
	},
	{
		imageKeywords:     []string{"samba", "dperson/samba", "servercontainers/samba"},
		schemaID:          "smb-conf",
		expectedBasenames: []string{"smb.conf"},
	},
	{
		imageKeywords:     []string{"minio"},
		schemaID:          "minio-env",
		expectedBasenames: []string{".env", "config.env"},
	},
	{
		imageKeywords:     []string{"mosquitto", "eclipse-mosquitto"},
		schemaID:          "mosquitto-conf",
		expectedBasenames: []string{"mosquitto.conf"},
	},
	{
		imageKeywords:     []string{"syncthing"},
		schemaID:          "syncthing-config",
		expectedBasenames: []string{"config.xml"},
	},
	{
		imageKeywords:     []string{"traefik"},
		schemaID:          "traefik-yml",
		expectedBasenames: []string{"traefik.yml", "traefik.yaml"},
	},
	// NFS server: containerised NFS daemons bind-mount the host exports file.
	// Common images: erichough/nfs-server, itsthenetwork/nfs-server-alpine, nfs-ganesha.
	{
		imageKeywords:     []string{"nfs-server", "nfs-ganesha", "erichough/nfs-server", "itsthenetwork/nfs"},
		schemaID:          "nfs-exports",
		expectedBasenames: []string{"exports"},
	},
}

// ServiceConfigCandidates derives ConfigCandidate values from the services in
// stack by correlating each service's bind-mount volumes with the curated
// kindTable.
//
// SAFETY INVARIANT: a compose-derived host path is emitted as a candidate ONLY
// when ALL of the following are true:
//  1. The VolumeMount.Type == "bind" (named volumes are never spelunked).
//  2. The Source path's basename is in the kind's expectedBasenames set.
//
// The caller (collect.collectServiceConfigs) enforces the third gate:
//  3. os.Lstat confirms the path is a regular file (not a directory or symlink).
//
// Named volumes (Type == "volume") are silently skipped; the SVC check for
// that service will return NotAssessed("config in a named volume").
//
// R3-5: when multiple kindSpecs match the same image and both claim the same
// expectedBasename (e.g. an image containing "sonarr" and "jenkins" both claim
// config.xml), only the most-specific match (longest keyword) is emitted to
// prevent cross-schema contamination.
func ServiceConfigCandidates(stack *model.Stack) []ConfigCandidate {
	var out []ConfigCandidate
	seen := map[string]bool{} // deduplicate by (schemaID, path)

	for _, svc := range stack.Services {
		base := intel.ImageBase(svc.Image)
		specs := kindsForImage(base)
		if len(specs) == 0 {
			continue
		}

		for _, vm := range svc.Volumes {
			if vm.Type != "bind" || vm.Source == "" {
				continue
			}
			src := vm.Source
			basename := filepath.Base(src)
			// A single bind-mount may match different kindSpecs (e.g. a vaultwarden
			// service may bind both .env and config.json under different schemaIDs).
			// R3-5: for collision resolution, track the best (longest keyword) spec
			// per basename when multiple specs claim the same filename.
			type specWithKW struct {
				spec  *kindSpec
				kwLen int
			}
			bestByBasename := make(map[string]specWithKW)
			for _, spec := range specs {
				if !inSet(basename, spec.expectedBasenames) {
					continue
				}
				// Find the longest keyword that matched this image for this spec.
				longestKW := 0
				for _, kw := range spec.imageKeywords {
					if containsSubstr(base, kw) && len(kw) > longestKW {
						longestKW = len(kw)
					}
				}
				existing, conflict := bestByBasename[basename]
				if !conflict || longestKW > existing.kwLen {
					bestByBasename[basename] = specWithKW{spec: spec, kwLen: longestKW}
				}
			}
			for _, best := range bestByBasename {
				key := best.spec.schemaID + "|" + src
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, ConfigCandidate{
					Path:     src,
					SchemaID: best.spec.schemaID,
					Kind:     base,
				})
			}
		}
	}
	return out
}

// kindsForImage returns all kindSpecs whose imageKeywords match the normalized
// image base. A service can match multiple specs when the image has more than
// one associated config format (e.g. vaultwarden: .env AND config.json).
func kindsForImage(imageBase string) []*kindSpec {
	var out []*kindSpec
	seen := map[string]bool{}
	for i := range kindTable {
		spec := &kindTable[i]
		for _, kw := range spec.imageKeywords {
			if containsSubstr(imageBase, kw) {
				if !seen[spec.schemaID] {
					seen[spec.schemaID] = true
					out = append(out, spec)
				}
				break
			}
		}
	}
	return out
}

// kindForImage returns the first kindSpec whose imageKeywords match the
// normalized image base, or nil if no kind matches. Callers that need all
// matching specs (e.g. when a service has multiple config formats) should
// use kindsForImage instead.
func kindForImage(imageBase string) *kindSpec {
	specs := kindsForImage(imageBase)
	if len(specs) == 0 {
		return nil
	}
	return specs[0]
}

// inSet reports whether s is in the set slice (case-sensitive).
func inSet(s string, set []string) bool {
	for _, v := range set {
		if s == v {
			return true
		}
	}
	return false
}

// containsSubstr reports whether haystack contains needle (both lower-cased by
// intel.ImageBase already — no extra folding needed here).
func containsSubstr(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(haystack == needle ||
			len(haystack) > len(needle) &&
				(haystack[:len(needle)] == needle ||
					haystack[len(haystack)-len(needle):] == needle ||
					containsAt(haystack, needle)))
}

func containsAt(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
