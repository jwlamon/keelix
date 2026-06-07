package collect

import (
	"strings"
	"testing"
)

func TestParseRedisConf_Unauthenticated(t *testing.T) {
	b := mustReadTestdata(t, "redis.conf")
	vals, schemaID, known := parseRedisConf(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "redis-conf" {
		t.Errorf("schemaID=%q, want redis-conf", schemaID)
	}
	if vals["requirepass.present"] != "false" {
		t.Errorf("requirepass.present=%q, want false", vals["requirepass.present"])
	}
	if vals["protected-mode"] != "no" {
		t.Errorf("protected-mode=%q, want no", vals["protected-mode"])
	}
	if vals["bind"] != "0.0.0.0" {
		t.Errorf("bind=%q, want 0.0.0.0", vals["bind"])
	}
}

func TestParseMongodConf_Unauthorized(t *testing.T) {
	b := mustReadTestdata(t, "mongod.conf")
	vals, schemaID, known := parseMongodConf(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "mongod-conf" {
		t.Errorf("schemaID=%q, want mongod-conf", schemaID)
	}
	// parseMongodConf emits "" for disabled/absent (derived boolean: "" = not enabled).
	if vals["security.authorization"] != "" {
		t.Errorf("security.authorization=%q, want empty string (not enabled)", vals["security.authorization"])
	}
}

func TestParsePgHba_TrustNonLocal(t *testing.T) {
	b := mustReadTestdata(t, "pg_hba.conf")
	vals, schemaID, known := parsePgHba(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "pg-hba" {
		t.Errorf("schemaID=%q, want pg-hba", schemaID)
	}
	if vals["trust.nonlocal"] != "true" {
		t.Errorf("trust.nonlocal=%q, want true", vals["trust.nonlocal"])
	}
}

func TestParseElasticsearchYml_SecurityDisabled(t *testing.T) {
	b := mustReadTestdata(t, "elasticsearch.yml")
	vals, schemaID, known := parseElasticsearchYml(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "elasticsearch-yml" {
		t.Errorf("schemaID=%q, want elasticsearch-yml", schemaID)
	}
	if vals["xpack.security.enabled"] != "false" {
		t.Errorf("xpack.security.enabled=%q, want false", vals["xpack.security.enabled"])
	}
}

func TestParseArrConfig_AuthNone(t *testing.T) {
	b := mustReadTestdata(t, "arr_config.xml")
	vals, schemaID, known := parseArrConfig(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "arr-config" {
		t.Errorf("schemaID=%q, want arr-config", schemaID)
	}
	if vals["AuthenticationMethod"] != "None" {
		t.Errorf("AuthenticationMethod=%q, want None", vals["AuthenticationMethod"])
	}
	if vals["ApiKey.present"] != "true" {
		t.Errorf("ApiKey.present=%q, want true", vals["ApiKey.present"])
	}
}

func TestParseQBittorrentConf_AuthOff(t *testing.T) {
	b := mustReadTestdata(t, "qbittorrent.conf")
	vals, schemaID, known := parseQBittorrentConf(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "qbittorrent-conf" {
		t.Errorf("schemaID=%q, want qbittorrent-conf", schemaID)
	}
	// LocalHostAuth=false means auth bypass is off -> webui.auth == "false"
	if vals["webui.auth"] != "false" {
		t.Errorf("webui.auth=%q, want false", vals["webui.auth"])
	}
}

func TestParseGrafanaIni_AnonEnabled(t *testing.T) {
	b := mustReadTestdata(t, "grafana.ini")
	vals, schemaID, known := parseGrafanaIni(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "grafana-ini" {
		t.Errorf("schemaID=%q, want grafana-ini", schemaID)
	}
	if vals["auth.anonymous.enabled"] != "true" {
		t.Errorf("auth.anonymous.enabled=%q, want true", vals["auth.anonymous.enabled"])
	}
	if vals["admin.default"] != "true" {
		t.Errorf("admin.default=%q, want true (default admin/admin creds)", vals["admin.default"])
	}
}

// TestParsePrometheusYml_NotDeterminable asserts that parsePrometheusYml always
// emits auth.determinable="false". prometheus.yml only holds outbound
// scrape-side auth; inbound API auth lives in a separate web.yml file. The
// parser cannot determine API auth status, so SVC021 must return NotAssessed.
func TestParsePrometheusYml_NotDeterminable(t *testing.T) {
	b := mustReadTestdata(t, "prometheus.yml")
	vals, schemaID, known := parsePrometheusYml(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "prometheus-yml" {
		t.Errorf("schemaID=%q, want prometheus-yml", schemaID)
	}
	if vals["auth.determinable"] != "false" {
		t.Errorf("auth.determinable=%q, want false (prometheus.yml cannot determine API auth)", vals["auth.determinable"])
	}
}

func TestParseVaultwardenEnv_WeakToken(t *testing.T) {
	b := mustReadTestdata(t, "vaultwarden.env")
	vals, schemaID, known := parseVaultwardenEnv(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "vaultwarden-env" {
		t.Errorf("schemaID=%q, want vaultwarden-env", schemaID)
	}
	if vals["admin_token.present"] != "true" {
		t.Errorf("admin_token.present=%q, want true", vals["admin_token.present"])
	}
	if vals["admin_token.is_argon2"] != "false" {
		t.Errorf("admin_token.is_argon2=%q, want false", vals["admin_token.is_argon2"])
	}
	if vals["admin_token.length_band"] != "weak" {
		t.Errorf("admin_token.length_band=%q, want weak (short token)", vals["admin_token.length_band"])
	}
	// Raw token MUST NOT appear in vals.
	for k, v := range vals {
		if strings.Contains(v, "weakpass") {
			t.Errorf("raw token leaked in vals[%q]=%q", k, v)
		}
	}
}

func TestParseGiteaIni_InstallUnlocked(t *testing.T) {
	b := mustReadTestdata(t, "gitea_app.ini")
	vals, schemaID, known := parseGiteaIni(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "gitea-ini" {
		t.Errorf("schemaID=%q, want gitea-ini", schemaID)
	}
	if vals["INSTALL_LOCK"] != "false" {
		t.Errorf("INSTALL_LOCK=%q, want false", vals["INSTALL_LOCK"])
	}
	if vals["registration.open"] != "true" {
		t.Errorf("registration.open=%q, want true", vals["registration.open"])
	}
}

func TestParseJenkinsConfig_NoSecurity(t *testing.T) {
	b := mustReadTestdata(t, "jenkins_config.xml")
	vals, schemaID, known := parseJenkinsConfig(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "jenkins-config" {
		t.Errorf("schemaID=%q, want jenkins-config", schemaID)
	}
	if vals["useSecurity"] != "false" {
		t.Errorf("useSecurity=%q, want false", vals["useSecurity"])
	}
}

func TestParseSmbConf_GuestShare(t *testing.T) {
	b := mustReadTestdata(t, "smb.conf")
	vals, schemaID, known := parseSmbConf(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "smb-conf" {
		t.Errorf("schemaID=%q, want smb-conf", schemaID)
	}
	if vals["guest-ok-shares"] == "" {
		t.Errorf("guest-ok-shares is empty, want at least one share name")
	}
	if !strings.Contains(vals["guest-ok-shares"], "public") {
		t.Errorf("guest-ok-shares=%q, want 'public' listed", vals["guest-ok-shares"])
	}
}

func TestParseNFSExports_NoRootSquash(t *testing.T) {
	b := mustReadTestdata(t, "nfs_exports")
	vals, schemaID, known := parseNFSExports(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "nfs-exports" {
		t.Errorf("schemaID=%q, want nfs-exports", schemaID)
	}
	if vals["no_root_squash"] != "true" {
		t.Errorf("no_root_squash=%q, want true", vals["no_root_squash"])
	}
	if vals["world-export"] != "true" {
		t.Errorf("world-export=%q, want true (wildcard host)", vals["world-export"])
	}
}

// TestParseNFSExports_WorldCIDR verifies that CIDR-notation world-exports
// (0.0.0.0/0, ::/0, 0/0) and the literal "all" host token are all treated as
// world-export=true by parseNFSExports.  Fixture: nfs_world_cidr.exports.
func TestParseNFSExports_WorldCIDR(t *testing.T) {
	b := mustReadTestdata(t, "nfs_world_cidr.exports")
	vals, schemaID, known := parseNFSExports(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "nfs-exports" {
		t.Errorf("schemaID=%q, want nfs-exports", schemaID)
	}
	if vals["world-export"] != "true" {
		t.Errorf("world-export=%q, want true (0.0.0.0/0/::/0/0/0/all must all trigger world-export)", vals["world-export"])
	}
}

func TestParseMinioEnv_DefaultCreds(t *testing.T) {
	b := mustReadTestdata(t, "minio.env")
	vals, schemaID, known := parseMinioEnv(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "minio-env" {
		t.Errorf("schemaID=%q, want minio-env", schemaID)
	}
	if vals["root-creds.default"] != "true" {
		t.Errorf("root-creds.default=%q, want true", vals["root-creds.default"])
	}
}

func TestParseMosquittoConf_AnonAllowed(t *testing.T) {
	b := mustReadTestdata(t, "mosquitto.conf")
	vals, schemaID, known := parseMosquittoConf(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "mosquitto-conf" {
		t.Errorf("schemaID=%q, want mosquitto-conf", schemaID)
	}
	if vals["allow_anonymous"] != "true" {
		t.Errorf("allow_anonymous=%q, want true", vals["allow_anonymous"])
	}
}

func TestParseSyncthingConfig_NoAuth(t *testing.T) {
	b := mustReadTestdata(t, "syncthing_config.xml")
	vals, schemaID, known := parseSyncthingConfig(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "syncthing-config" {
		t.Errorf("schemaID=%q, want syncthing-config", schemaID)
	}
	if vals["gui.auth"] != "false" {
		t.Errorf("gui.auth=%q, want false (no user/password set)", vals["gui.auth"])
	}
}

func TestParseTraefikYml_InsecureAPI(t *testing.T) {
	b := mustReadTestdata(t, "traefik.yml")
	vals, schemaID, known := parseTraefikYml(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "traefik-yml" {
		t.Errorf("schemaID=%q, want traefik-yml", schemaID)
	}
	if vals["api.insecure"] != "true" {
		t.Errorf("api.insecure=%q, want true", vals["api.insecure"])
	}
}
