package collect

import (
	"encoding/json"
	"strings"
)

// parseRedisConf parses redis.conf.
// SchemaID: "redis-conf"
// Emitted keys:
//
//	requirepass.present ("true"/"false")
//	protected-mode ("yes"/"no"/"")
//	bind (raw value, e.g. "127.0.0.1" or "0.0.0.0")
func parseRedisConf(b []byte) (map[string]string, string, bool) {
	m := parseINI(b)
	if len(m) == 0 {
		return nil, "", false
	}
	rp, hasRP := m["requirepass"]
	rpPresent := "false"
	if hasRP && strings.TrimSpace(rp) != "" {
		rpPresent = "true"
	}
	out := map[string]string{
		"requirepass.present": rpPresent,
		"protected-mode":      m["protected-mode"],
		"bind":                m["bind"],
	}
	return out, "redis-conf", true
}

// parseMongodConf parses mongod.conf (YAML format).
// SchemaID: "mongod-conf"
// Emitted keys:
//
//	security.authorization ("enabled"/"") — "enabled" when the YAML field is
//	  set to "enabled"; "" otherwise (disabled or absent).
//
// Implementation note: the key "security.authorization" ends in "authorization"
// which classOf treats as a credential field, redacting any non-empty value to
// "[secret]". To avoid that, we emit "" (not redacted — classOf returns "empty"
// for empty strings) for the not-enabled case and rely on the check firing when
// the value is not "enabled". The enabled value WILL be redacted to "[secret]",
// but the check compares != "" (i.e. fires only when empty/absent), so it
// correctly does not fire when auth is explicitly enabled.
// The check reads: `cf.Values["security.authorization"] == ""` → fire.
func parseMongodConf(b []byte) (map[string]string, string, bool) {
	m := parseYAML(b)
	if len(m) == 0 {
		return nil, "", false
	}
	authVal := ""
	if strings.TrimSpace(m["security.authorization"]) == "enabled" {
		authVal = "enabled"
	}
	out := map[string]string{
		"security.authorization": authVal,
	}
	return out, "mongod-conf", true
}

// parseElasticsearchYml parses elasticsearch.yml.
// SchemaID: "elasticsearch-yml"
// Emitted keys:
//
//	xpack.security.enabled ("true"/"false"/"")
func parseElasticsearchYml(b []byte) (map[string]string, string, bool) {
	m := parseYAML(b)
	if len(m) == 0 {
		return nil, "", false
	}
	out := map[string]string{
		"xpack.security.enabled": m["xpack.security.enabled"],
	}
	return out, "elasticsearch-yml", true
}

// parseArrConfig parses *arr config.xml (Sonarr/Radarr/Prowlarr/Lidarr/Readarr).
// SchemaID: "arr-config"
// Emitted keys:
//
//	AuthenticationMethod ("None"/"Basic"/"Forms") — defaults to "None" when absent
//	  (legacy *arr installs omit the element; the implied behaviour is no auth).
//	ApiKey.present ("true"/"false")
func parseArrConfig(b []byte) (map[string]string, string, bool) {
	m, ok := parseXML(b)
	if !ok {
		return nil, "", false
	}
	// XML keys are prefixed by root element; find them by suffix.
	// Default to "None": a missing AuthenticationMethod element means the legacy
	// implied "no authentication" — we must not silently pass such configs.
	authMethod := "None"
	authFound := false
	apiKeyPresent := "false"
	for k, v := range m {
		if strings.HasSuffix(k, ".AuthenticationMethod") || k == "AuthenticationMethod" {
			authMethod = v
			authFound = true
		}
		if strings.HasSuffix(k, ".ApiKey") || k == "ApiKey" {
			if strings.TrimSpace(v) != "" {
				apiKeyPresent = "true"
			}
		}
	}
	// Suppress the linter false positive: authFound is read below to document
	// intent; the default "None" is the meaningful path when !authFound.
	_ = authFound
	out := map[string]string{
		"AuthenticationMethod": authMethod,
		"ApiKey.present":       apiKeyPresent,
	}
	// R2-7: extract <Port> so SVC010 can use the actual service port rather than
	// hardcoding 7878 for all *arr variants (Sonarr=8989, Prowlarr=9696, etc.).
	// R3-5: prefer exact root-child key "Config.Port"; fall back to suffix scan
	// ONLY for direct root children (strings.Count(k,".")==1) to avoid picking up
	// deeply nested elements like Config.Nested.Port.
	if v, ok2 := m["Config.Port"]; ok2 && strings.TrimSpace(v) != "" {
		out["Port"] = strings.TrimSpace(v)
	} else {
		for k, v := range m {
			if strings.Count(k, ".") == 1 && strings.HasSuffix(k, ".Port") {
				if strings.TrimSpace(v) != "" {
					out["Port"] = strings.TrimSpace(v)
				}
			}
		}
	}
	return out, "arr-config", true
}

// parseQBittorrentConf parses qBittorrent's conf file (INI, Windows-style with backslash keys).
// SchemaID: "qbittorrent-conf"
// Emitted keys:
//
//	webui.auth ("true"/"false") — false when LocalHostAuth=false (auth disabled)
func parseQBittorrentConf(b []byte) (map[string]string, string, bool) {
	m := parseINI(b)
	if len(m) == 0 {
		return nil, "", false
	}
	// qBittorrent uses backslash-separated keys in the INI, e.g.:
	// "Preferences.WebUI\LocalHostAuth".
	// parseINI stores them with backslashes as part of the key value.
	// Normalize: treat backslash as path separator for lookup.
	normalized := make(map[string]string, len(m))
	for k, v := range m {
		nk := strings.ReplaceAll(k, `\`, ".")
		normalized[nk] = v
	}
	// LocalHostAuth=false → auth is off (bypass localhost-only restriction).
	// Section names are lowercased by parseINI, so look up "preferences.*".
	localAuth := normalized["preferences.WebUI.LocalHostAuth"]
	webuiAuth := "true"
	if strings.ToLower(localAuth) == "false" {
		webuiAuth = "false"
	}
	out := map[string]string{
		"webui.auth": webuiAuth,
	}
	return out, "qbittorrent-conf", true
}

// parseGrafanaIni parses grafana.ini.
// SchemaID: "grafana-ini"
// Emitted keys:
//
//	auth.anonymous.enabled ("true"/"false")
//	admin.default ("true"/"false") — true when admin_user==admin OR admin_password==admin,
//	  OR when either key is absent (Grafana built-in default is admin/admin).
//	  Safe (false) only when BOTH user AND password differ from "admin".
func parseGrafanaIni(b []byte) (map[string]string, string, bool) {
	m := parseINI(b)
	if len(m) == 0 {
		return nil, "", false
	}
	anonEnabled := "false"
	if strings.ToLower(m["auth.anonymous.enabled"]) == "true" {
		anonEnabled = "true"
	}
	// Grafana's built-in default for admin_user is "admin" and admin_password is
	// "admin". When either key is absent from the file the operator has not
	// overridden the default → treat as default credentials (admin.default=true).
	user, userSet := m["security.admin_user"]
	pass, passSet := m["security.admin_password"]
	adminDefault := "true" // assume default until proven otherwise
	if userSet && passSet {
		// Both explicitly set: only safe when BOTH differ from "admin".
		// If either equals "admin" the credential pair is still partially default.
		if strings.ToLower(user) != "admin" && strings.ToLower(pass) != "admin" {
			adminDefault = "false"
		}
	} else if userSet {
		// Only user set: password absent → still default password.
		_ = user
	} else if passSet {
		// Only password set: username absent → still default username.
		_ = pass
	}
	// else: neither set → built-in defaults apply → adminDefault stays "true"
	out := map[string]string{
		"auth.anonymous.enabled": anonEnabled,
		"admin.default":          adminDefault,
	}
	return out, "grafana-ini", true
}

// parsePrometheusYml parses prometheus.yml.
// SchemaID: "prometheus-yml"
// Emitted keys:
//
//	auth.determinable ("false") — always "false": prometheus.yml only holds
//	  outbound scrape-side auth (basic_auth, tls_config, bearer_token). Inbound
//	  API authentication is configured in a separate web.yml file passed via
//	  --web.config.file. SVC021 cannot determine API auth from prometheus.yml
//	  alone and must return NotAssessed.
func parsePrometheusYml(b []byte) (map[string]string, string, bool) {
	m := parseYAML(b)
	if len(m) == 0 {
		return nil, "", false
	}
	// Consume m to avoid unused-variable lint noise.
	_ = m
	// API auth is always indeterminable from prometheus.yml alone.
	out := map[string]string{"auth.determinable": "false"}
	return out, "prometheus-yml", true
}

// parseVaultwardenEnv parses the Vaultwarden environment file.
// SchemaID: "vaultwarden-env"
// Emitted keys (DERIVED — raw token is NEVER emitted):
//
//	admin_token.present ("true"/"false")
//	admin_token.is_argon2 ("true"/"false") — true when value starts with "$argon2"
//	admin_token.length_band ("none"/"weak"/"ok")
//	  none  = not present
//	  weak  = present but shorter than 20 chars
//	  ok    = present and >= 20 chars
func parseVaultwardenEnv(b []byte) (map[string]string, string, bool) {
	// Use parseDotenv-style line parsing (KEY=VALUE).
	raw := make(map[string]string)
	for _, line := range splitLines(string(b)) {
		line = trimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		eq := indexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := trimSpace(line[:eq])
		val := trimSpace(line[eq+1:])
		raw[strings.ToUpper(key)] = val
	}
	if len(raw) == 0 {
		return nil, "", false
	}
	token, hasToken := raw["ADMIN_TOKEN"]
	present := "false"
	isArgon2 := "false"
	lengthBand := "none"
	if hasToken && token != "" {
		present = "true"
		if strings.HasPrefix(token, "$argon2") {
			isArgon2 = "true"
			lengthBand = "ok"
		} else if len(token) >= 20 {
			lengthBand = "ok"
		} else {
			lengthBand = "weak"
		}
	}
	out := map[string]string{
		"admin_token.present":     present,
		"admin_token.is_argon2":   isArgon2,
		"admin_token.length_band": lengthBand,
	}
	return out, "vaultwarden-env", true
}

// parseVaultwardenJSON parses Vaultwarden's config.json (admin-panel default).
// SchemaID: "vaultwarden-json"
// Emitted keys (DERIVED — raw token is NEVER emitted):
//
//	admin_token.present ("true"/"false")
//	admin_token.is_argon2 ("true"/"false") — true when value starts with "$argon2"
//	admin_token.length_band ("none"/"weak"/"ok")
//	  none  = not present
//	  weak  = present but shorter than 20 chars
//	  ok    = present and >= 20 chars
func parseVaultwardenJSON(b []byte) (map[string]string, string, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) == 0 {
		return nil, "", false
	}
	// Extract admin_token — it may be a string or absent.
	present := "false"
	isArgon2 := "false"
	lengthBand := "none"
	if tokenRaw, ok := raw["admin_token"]; ok {
		var token string
		if err := json.Unmarshal(tokenRaw, &token); err == nil && token != "" {
			present = "true"
			if strings.HasPrefix(token, "$argon2") {
				isArgon2 = "true"
				lengthBand = "ok"
			} else if len(token) >= 20 {
				lengthBand = "ok"
			} else {
				lengthBand = "weak"
			}
		}
	}
	out := map[string]string{
		"admin_token.present":     present,
		"admin_token.is_argon2":   isArgon2,
		"admin_token.length_band": lengthBand,
	}
	return out, "vaultwarden-json", true
}

// parseGiteaIni parses Gitea's app.ini.
// SchemaID: "gitea-ini"
// Emitted keys:
//
//	INSTALL_LOCK ("true"/"false") — emitted ONLY when the key is explicitly
//	  present in the file; absent when the key is missing so that SVC031 can
//	  return NotAssessed rather than firing a spurious warning.
//	registration.open ("true"/"false") — true when DISABLE_REGISTRATION != true
func parseGiteaIni(b []byte) (map[string]string, string, bool) {
	m := parseINI(b)
	if len(m) == 0 {
		return nil, "", false
	}
	disableReg := strings.ToLower(m["service.DISABLE_REGISTRATION"])
	regOpen := "true"
	if disableReg == "true" {
		regOpen = "false"
	}
	out := map[string]string{
		"registration.open": regOpen,
	}
	// Only emit INSTALL_LOCK when it is explicitly set in the config file.
	// An absent key must NOT default to "false" — that causes SVC031 to fire
	// on a correctly-installed gitea that simply omits the key.
	if raw, ok := m["security.INSTALL_LOCK"]; ok {
		out["INSTALL_LOCK"] = strings.ToLower(raw)
	}
	return out, "gitea-ini", true
}

// parseJenkinsConfig parses Jenkins' config.xml.
// SchemaID: "jenkins-config"
// Emitted keys:
//
//	useSecurity ("true"/"false")
func parseJenkinsConfig(b []byte) (map[string]string, string, bool) {
	// Go's encoding/xml only supports XML 1.0; Jenkins uses 1.1.
	// Strip the XML declaration so the decoder sees no version constraint.
	s := string(b)
	if strings.HasPrefix(strings.TrimSpace(s), "<?xml") {
		end := strings.Index(s, "?>")
		if end >= 0 {
			s = strings.TrimSpace(s[end+2:])
		}
	}
	m, ok := parseXML([]byte(s))
	if !ok {
		return nil, "", false
	}
	useSecVal := ""
	for k, v := range m {
		seg := k
		if dot := strings.LastIndex(k, "."); dot >= 0 {
			seg = k[dot+1:]
		}
		if seg == "useSecurity" {
			useSecVal = strings.ToLower(v)
		}
	}
	if useSecVal == "" {
		useSecVal = "true" // absent = default-secure
	}
	out := map[string]string{"useSecurity": useSecVal}
	return out, "jenkins-config", true
}

// parseSmbConf parses smb.conf.
// SchemaID: "smb-conf"
// Emitted keys:
//
//	guest-ok-shares (comma-separated list of share names with "guest ok = yes")
func parseSmbConf(b []byte) (map[string]string, string, bool) {
	m := parseINI(b)
	if len(m) == 0 {
		return nil, "", false
	}
	// Collect sections with "guest ok = yes" / "guest ok = true".
	// parseINI stores section.key, so we scan for keys ending in "guest ok".
	// When dot<0 the key has no section prefix — it belongs to the implicit
	// top-level "(global)" section rather than being skipped (bug: was continue).
	guestShares := []string{}
	sectionKeys := make(map[string]string) // section -> "guest ok" value
	for k, v := range m {
		dot := strings.LastIndex(k, ".")
		var section, field string
		if dot < 0 {
			// Top-level (pre-section) key — attribute to the implicit global section.
			section = "(global)"
			field = strings.ToLower(strings.TrimSpace(k))
		} else {
			section = k[:dot]
			field = strings.ToLower(strings.TrimSpace(k[dot+1:]))
		}
		if field == "guest ok" {
			sectionKeys[section] = strings.ToLower(v)
		}
	}
	for sec, v := range sectionKeys {
		if v == "yes" || v == "true" {
			// Use the last path segment as the share name.
			name := sec
			if dot := strings.LastIndex(sec, "."); dot >= 0 {
				name = sec[dot+1:]
			}
			guestShares = append(guestShares, name)
		}
	}
	sortStrings(guestShares)
	out := map[string]string{
		"guest-ok-shares": strings.Join(guestShares, ","),
	}
	return out, "smb-conf", true
}

// parseNFSExports parses /etc/exports.
// SchemaID: "nfs-exports"
// Emitted keys:
//
//	no_root_squash ("true"/"false")
//	world-export ("true"/"false") — true when any export has a wildcard host (*)
func parseNFSExports(b []byte) (map[string]string, string, bool) {
	lines := parseNonEmptyLines(b)
	if len(lines) == 0 {
		return nil, "", false
	}
	noRootSquash := "false"
	worldExport := "false"
	for _, line := range lines {
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "no_root_squash") {
			noRootSquash = "true"
		}
		// World export: host field is "*", "*(options)", a known world-CIDR
		// (0.0.0.0/0, ::/0, 0/0), or the literal "all" / "all(options)".
		// These all grant access from any host.
		fields := strings.Fields(line)
		for _, f := range fields[1:] { // skip the path
			host := f
			if idx := strings.IndexByte(f, '('); idx >= 0 {
				host = f[:idx]
			}
			switch {
			case host == "*",
				host == "0.0.0.0/0",
				host == "::/0",
				host == "0/0",
				strings.EqualFold(host, "all"):
				worldExport = "true"
			}
		}
	}
	out := map[string]string{
		"no_root_squash": noRootSquash,
		"world-export":   worldExport,
	}
	return out, "nfs-exports", true
}

// parseMinioEnv parses MinIO's environment file.
// SchemaID: "minio-env"
// Emitted keys:
//
//	root-creds.default ("true"/"false") — true when user==minioadmin AND pass==minioadmin
func parseMinioEnv(b []byte) (map[string]string, string, bool) {
	raw := make(map[string]string)
	for _, line := range splitLines(string(b)) {
		line = trimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		eq := indexByte(line, '=')
		if eq <= 0 {
			continue
		}
		raw[trimSpace(line[:eq])] = trimSpace(line[eq+1:])
	}
	if len(raw) == 0 {
		return nil, "", false
	}
	user := strings.ToLower(raw["MINIO_ROOT_USER"])
	pass := strings.ToLower(raw["MINIO_ROOT_PASSWORD"])
	isDefault := "false"
	if user == "minioadmin" && pass == "minioadmin" {
		isDefault = "true"
	}
	out := map[string]string{"root-creds.default": isDefault}
	return out, "minio-env", true
}

// parseMosquittoConf parses mosquitto.conf.
// SchemaID: "mosquitto-conf"
// Emitted keys:
//
//	allow_anonymous ("true"/"false")
func parseMosquittoConf(b []byte) (map[string]string, string, bool) {
	m := parseINI(b)
	if len(m) == 0 {
		return nil, "", false
	}
	anon := strings.ToLower(m["allow_anonymous"])
	if anon == "" {
		anon = "false"
	}
	out := map[string]string{"allow_anonymous": anon}
	return out, "mosquitto-conf", true
}

// parseSyncthingConfig parses Syncthing's config.xml.
// SchemaID: "syncthing-config"
// Emitted keys:
//
//	gui.auth ("true"/"false") — false when gui/user element is empty
func parseSyncthingConfig(b []byte) (map[string]string, string, bool) {
	m, ok := parseXML(b)
	if !ok {
		return nil, "", false
	}
	guiAuth := "false"
	for k, v := range m {
		kl := strings.ToLower(k)
		if strings.HasSuffix(kl, ".user") || kl == "user" {
			if strings.TrimSpace(v) != "" {
				guiAuth = "true"
			}
		}
	}
	out := map[string]string{"gui.auth": guiAuth}
	return out, "syncthing-config", true
}

// parseTraefikYml parses traefik.yml.
// SchemaID: "traefik-yml"
// Emitted keys:
//
//	api.insecure ("true"/"false"/"")
func parseTraefikYml(b []byte) (map[string]string, string, bool) {
	m := parseYAML(b)
	if len(m) == 0 {
		return nil, "", false
	}
	insecure := strings.ToLower(m["api.insecure"])
	if insecure == "" {
		insecure = "false"
	}
	out := map[string]string{"api.insecure": insecure}
	return out, "traefik-yml", true
}

// parsePgHba parses pg_hba.conf.
// SchemaID: "pg-hba"
// Emitted keys:
//
//	trust.nonlocal ("true"/"false") — true if any non-local host entry uses trust auth
func parsePgHba(b []byte) (map[string]string, string, bool) {
	lines := parseNonEmptyLines(b)
	if len(lines) == 0 {
		return nil, "", false
	}
	trustNonLocal := "false"
	for _, line := range lines {
		fields := strings.Fields(line)
		// pg_hba fields: type database user address method [options]
		// "local" entries have no address field; "host*" entries do.
		if len(fields) < 4 {
			continue
		}
		connType := strings.ToLower(fields[0])
		if connType == "local" {
			continue
		}
		// host / hostssl / hostnossl / hostgssenc
		if !strings.HasPrefix(connType, "host") {
			continue
		}
		// method is the last field in a standard line (5th field for host).
		method := ""
		if len(fields) >= 5 {
			method = strings.ToLower(fields[4])
		}
		if method == "trust" {
			trustNonLocal = "true"
		}
	}
	out := map[string]string{"trust.nonlocal": trustNonLocal}
	return out, "pg-hba", true
}
