// Package catalog is the single source of truth for every check Keelix
// performs: its stable ID, group, title, default severity, the deterministic
// rationale ("why this matters"), and the compliance controls it maps to
// (SOC 2 Trust Services Criteria, ISO 27001 Annex A:2022, CIS Docker Benchmark
// v1.6.0). Check implementations build findings from catalog entries so that
// IDs and control mappings never drift between the detection logic and the
// Compliance Evidence Bridge.
//
// This catalog is versioned via CatalogVersion. Bump it when entries change.
package catalog

import (
	"sort"

	"github.com/jwlamon/keelix/internal/model"
)

// CatalogVersion identifies this revision of the check + control mapping library.
const CatalogVersion = "2.4.0"

// Entry is the canonical definition of one check.
type Entry struct {
	ID       string
	Group    model.CheckGroup
	Title    string
	Severity model.Severity // default; checks may override per-finding
	// Rationale is the deterministic plain-English reason this matters. It is
	// used as the baseline Finding.Detail (the AI layer may enrich it).
	Rationale string
	Controls  []model.ControlRef
	// BaseImpact is the 0-10 intrinsic impact used by the v2 score.
	BaseImpact float64
	// Fatal marks a check whose high-confidence failure can drive an overall RED cap.
	Fatal bool
}

// soc2 builds a SOC 2 control reference.
func soc2(id, title string) model.ControlRef {
	return model.ControlRef{Framework: "SOC2", ID: id, Title: title}
}

// iso builds an ISO 27001 Annex A control reference.
func iso(id, title string) model.ControlRef {
	return model.ControlRef{Framework: "ISO27001", ID: id, Title: title}
}

// cis builds a CIS Docker Benchmark control reference.
func cis(id, title string) model.ControlRef {
	return model.ControlRef{Framework: "CIS-Docker", ID: id, Title: title}
}

// cisl builds a CIS Debian/Linux Benchmark control reference.
// Used for HST-series check mappings (distinct from cis() = CIS-Docker).
func cisl(id, title string) model.ControlRef {
	return model.ControlRef{Framework: "CIS-Linux", ID: id, Title: title}
}

// defaultBaseImpact derives a 0-10 intrinsic impact from a check's default
// severity when the entry does not set one explicitly: Critical 9, Warning 5,
// Info 2 (anything else 2).
func defaultBaseImpact(s model.Severity) float64 {
	switch s {
	case model.SeverityCritical:
		return 9.0
	case model.SeverityWarning:
		return 5.0
	default:
		return 2.0
	}
}

// Reusable control references.
var (
	cBoundary   = soc2("CC6.6", "Boundary protection / external threats")
	cLogical    = soc2("CC6.1", "Logical access controls")
	cTransit    = soc2("CC6.7", "Data in transit encryption")
	cMalicious  = soc2("CC6.8", "Prevention of unauthorized/malicious software")
	cVulnDetect = soc2("CC7.1", "Vulnerability detection")
	cMonitor    = soc2("CC7.2", "Security event monitoring")

	cNetSec     = iso("A.8.20", "Network security")
	cNetSvc     = iso("A.8.21", "Security of network services")
	cSegregate  = iso("A.8.22", "Segregation of networks")
	cConfig     = iso("A.8.9", "Configuration management")
	cCrypto     = iso("A.8.24", "Use of cryptography")
	cAuthInfo   = iso("A.5.17", "Authentication information")
	cSecureAuth = iso("A.8.5", "Secure authentication")
	cPrivAccess = iso("A.8.2", "Privileged access rights")
	cVulnMgmt   = iso("A.8.8", "Management of technical vulnerabilities")
)

// entries is the full catalog keyed by check ID.
var entries = func() map[string]Entry {
	list := []Entry{
		// ---- Network exposure (EXP) ----
		{
			ID: "EXP001", Group: model.GroupExposure,
			Title:     "Sensitive internal service reachable from the internet",
			Severity:  model.SeverityCritical,
			Rationale: "Datastores, caches and admin services (Postgres, Redis, MongoDB, Elasticsearch, MySQL, message brokers, admin panels) are designed to sit on a private network. When they answer connections from the public internet, anyone can attempt authentication, exploit known CVEs, or exfiltrate data directly.",
			Controls:  []model.ControlRef{cBoundary, cNetSec, cSegregate, cis("5.7", "Privileged ports / unnecessary exposure")},
		},
		{
			ID: "EXP002", Group: model.GroupExposure,
			Title:     "Undeclared port reachable from the internet",
			Severity:  model.SeverityWarning,
			Rationale: "A port is reachable from the public internet that the Compose file does not publish. This is a surprise exposure — a host-level service, a leftover container, or a firewall gap — and surprises are where breaches start.",
			Controls:  []model.ControlRef{cBoundary, cNetSec, cMonitor},
		},
		{
			ID: "EXP003", Group: model.GroupExposure,
			Title:     "Declared public port not reachable from the internet",
			Severity:  model.SeverityInfo,
			Rationale: "Compose publishes a port that is not actually reachable from outside. Usually benign (firewall is doing its job, or the service is down), but the declared/observed mismatch is worth surfacing so intent and reality stay aligned.",
			Controls:  []model.ControlRef{cBoundary},
		},

		// ---- Docker / firewall bypass (FW) ----
		{
			ID: "FW001", Group: model.GroupFirewall,
			Title:     "Docker bypasses the host firewall for a published port",
			Severity:  model.SeverityCritical,
			Rationale: "Docker writes iptables rules in the DOCKER chain that are evaluated before UFW's rules. A `ufw deny <port>` therefore does nothing for a container that publishes that port — the service is reachable even though the operator believes the firewall blocks it. This is the single most common way self-hosted databases end up on the public internet.",
			Controls:  []model.ControlRef{cBoundary, cNetSec, cConfig},
		},
		{
			ID: "FW002", Group: model.GroupFirewall,
			Title:     "Sensitive port bound to all interfaces (0.0.0.0)",
			Severity:  model.SeverityWarning,
			Rationale: "Publishing a sensitive port without a bind address exposes it on every host interface, including the public one. Internal services should bind to 127.0.0.1 and be reached through a reverse proxy or SSH tunnel.",
			Controls:  []model.ControlRef{cBoundary, cNetSec},
		},
		{
			ID: "FW003", Group: model.GroupFirewall,
			Title:     "Service uses host network mode",
			Severity:  model.SeverityWarning,
			Rationale: "`network_mode: host` removes Docker's network isolation: the container shares the host's network stack, every port it opens is published directly, and port-level firewalling no longer applies as expected.",
			Controls:  []model.ControlRef{cNetSec, cSegregate, cis("5.9", "Host network namespace not shared")},
		},
		{
			ID: "FW004", Group: model.GroupFirewall,
			Title:     "No DOCKER-USER firewall rule restricting published ports",
			Severity:  model.SeverityInfo,
			Rationale: "Because Docker bypasses UFW, the correct place to restrict container-published ports is the DOCKER-USER iptables chain. No such rule was found, so any published port is open to the world unless individually bound to localhost.",
			Controls:  []model.ControlRef{cBoundary, cNetSec, cConfig},
		},
		{
			ID: "FW005", Group: model.GroupFirewall,
			Title:      "Docker daemon API exposed over TCP",
			Severity:   model.SeverityCritical,
			BaseImpact: 9.5,
			Rationale:  "The Docker daemon is configured to accept connections on a TCP socket that is reachable beyond the local machine (port 2375 or 2376). The API provides full control of every container and the Docker runtime — the equivalent of unauthenticated root on the host. An attacker that can reach the socket can start privileged containers, read secrets from running containers, and pivot to the host with a single API call.",
			Controls:   []model.ControlRef{cBoundary, cNetSec, cPrivAccess, cis("3.6", "Ensure Docker daemon is not exposed over TCP")},
		},
		{
			ID: "FW006", Group: model.GroupFirewall,
			Title:      "k3s/kubelet anonymous authentication enabled",
			Severity:   model.SeverityCritical,
			BaseImpact: 8.0,
			Rationale:  "The k3s or kubelet API server is configured with --anonymous-auth=true or lacks --authorization-mode=Webhook, allowing unauthenticated access to the Kubelet API (port 10250). This endpoint can be used to execute arbitrary commands in any pod on the node, read secrets, and exfiltrate workload data without credentials.",
			Controls:   []model.ControlRef{cBoundary, cLogical, cNetSec},
		},

		// ---- Reverse proxy (PRX) ----
		{
			ID: "PRX001", Group: model.GroupProxy,
			Title:     "Public route has no authentication in front of it",
			Severity:  model.SeverityWarning,
			Rationale: "The reverse proxy routes traffic to a service with no authentication middleware. Anything exposed this way is open to anyone who knows the URL — the classic 'I thought it was private' dashboard leak.",
			Controls:  []model.ControlRef{cLogical, cSecureAuth, cNetSvc},
		},
		{
			ID: "PRX002", Group: model.GroupProxy,
			Title:     "Public route served over plain HTTP",
			Severity:  model.SeverityWarning,
			Rationale: "A publicly routed service is served without TLS, so credentials and data travel in cleartext and are trivially intercepted on any network between the client and the host.",
			Controls:  []model.ControlRef{cTransit, cCrypto},
		},
		{
			ID: "PRX003", Group: model.GroupProxy,
			Title:     "Reverse-proxy admin dashboard exposed insecurely",
			Severity:  model.SeverityCritical,
			Rationale: "The proxy's own dashboard/API is exposed without authentication (e.g. Traefik `api.insecure=true`). This hands an attacker a live map of every routed service and, in many cases, the ability to reconfigure routing.",
			Controls:  []model.ControlRef{cLogical, cBoundary, cConfig},
		},
		{
			ID: "PRX004", Group: model.GroupProxy,
			Title:     "Missing security headers on public route",
			Severity:  model.SeverityInfo,
			Rationale: "The route does not set baseline security headers (HSTS, X-Content-Type-Options, X-Frame-Options). These reduce the blast radius of common web attacks and are expected by most security reviews.",
			Controls:  []model.ControlRef{cConfig, cNetSvc},
		},
		{
			ID: "PRX005", Group: model.GroupProxy,
			Title:     "Overly broad / wildcard proxy route",
			Severity:  model.SeverityWarning,
			Rationale: "A wildcard or catch-all host rule can unintentionally route traffic to internal services and makes it easy to expose something new without realizing it.",
			Controls:  []model.ControlRef{cNetSec, cConfig},
		},
		{
			ID: "PRX006", Group: model.GroupProxy,
			Title:     "Reverse proxy uses default credentials",
			Severity:  model.SeverityCritical,
			Rationale: "The proxy (e.g. Nginx Proxy Manager) still uses well-known default credentials, giving an attacker full control of routing and TLS.",
			Controls:  []model.ControlRef{cLogical, cAuthInfo},
		},

		// ---- Container hardening (HRD) ----
		{
			ID: "HRD001", Group: model.GroupHardening,
			Title:     "Container runs in privileged mode",
			Severity:  model.SeverityCritical,
			Rationale: "`privileged: true` gives the container almost all host capabilities and device access. A compromise of the process is effectively a compromise of the host.",
			Controls:  []model.ControlRef{cPrivAccess, cConfig, cis("5.4", "Privileged containers not used")},
		},
		{
			ID: "HRD002", Group: model.GroupHardening,
			Title:     "Dangerous Linux capability added",
			Severity:  model.SeverityWarning,
			Rationale: "Capabilities such as SYS_ADMIN, NET_ADMIN, SYS_PTRACE or ALL substantially widen what a compromised container can do to the host kernel and other containers.",
			Controls:  []model.ControlRef{cPrivAccess, cConfig, cis("5.3", "Linux kernel capabilities restricted")},
		},
		{
			ID: "HRD003", Group: model.GroupHardening,
			Title:     "Docker socket mounted into a container",
			Severity:  model.SeverityCritical,
			Rationale: "Mounting /var/run/docker.sock gives the container full control of the Docker daemon, which is equivalent to root on the host. A single application vulnerability becomes a full host takeover.",
			Controls:  []model.ControlRef{cPrivAccess, cConfig, cis("5.31", "Docker socket not mounted in containers")},
		},
		{
			ID: "HRD004", Group: model.GroupHardening,
			Title:     "Container runs as root",
			Severity:  model.SeverityWarning,
			Rationale: "Running as UID 0 means a process escape lands as root inside the container and maximizes the impact of any kernel or runtime vulnerability. Run as a dedicated non-root user instead.",
			Controls:  []model.ControlRef{cPrivAccess, cConfig},
		},
		{
			ID: "HRD005", Group: model.GroupHardening,
			Title:     "Root filesystem is not read-only",
			Severity:  model.SeverityInfo,
			Rationale: "A writable root filesystem lets an attacker drop tools, modify binaries, or persist. Most services run fine with `read_only: true` plus explicit writable volumes.",
			Controls:  []model.ControlRef{cConfig, cis("5.12", "Container root filesystem mounted read-only")},
		},
		{
			ID: "HRD006", Group: model.GroupHardening,
			Title:     "Missing no-new-privileges",
			Severity:  model.SeverityInfo,
			Rationale: "Without `security_opt: [no-new-privileges:true]` a process inside the container can gain privileges via setuid binaries, undermining a non-root user.",
			Controls:  []model.ControlRef{cConfig, cis("5.25", "Restrict acquiring additional privileges")},
		},
		{
			ID: "HRD007", Group: model.GroupHardening,
			Title:     "No resource limits set",
			Severity:  model.SeverityInfo,
			Rationale: "Without memory/CPU limits a single container can exhaust host resources, enabling a noisy-neighbor denial of service against everything else on the host.",
			Controls:  []model.ControlRef{cConfig, cis("5.10", "Memory usage limited"), cis("5.11", "CPU priority set")},
		},
		{
			ID: "HRD008", Group: model.GroupHardening,
			Title:     "Mutable image tag (:latest or untagged)",
			Severity:  model.SeverityWarning,
			Rationale: "`:latest` (or no tag) means the running image can change without warning, breaking reproducibility and silently pulling in vulnerable or malicious versions. Pin to an explicit version.",
			Controls:  []model.ControlRef{cConfig, cVulnMgmt},
		},
		{
			ID: "HRD009", Group: model.GroupHardening,
			Title:      "docker.sock world- or group-accessible",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.5,
			Rationale:  "/var/run/docker.sock has permissions that allow any user in the docker group (or world) to connect to it. The Docker socket gives full control of the Docker daemon — equivalent to root on the host. Correct permissions are 0660 root:docker so only explicit group members can access it.",
			Controls:   []model.ControlRef{cPrivAccess, cConfig, cis("3.15", "Ensure Docker socket file ownership is set to root:docker")},
		},
		{
			ID: "HRD010", Group: model.GroupHardening,
			Title:      "Interactive user in docker group (root-equivalent)",
			Severity:   model.SeverityWarning,
			BaseImpact: 7.0,
			Rationale:  "A non-root interactive login user is a member of the docker group, which provides full Docker daemon access equivalent to unrestricted root on the host. Unlike a dedicated service account, an interactive user is also subject to password brute-force, phishing, and SSH attacks that land with immediate docker-group privilege.",
			Controls:   []model.ControlRef{cPrivAccess, cConfig, cis("3.5", "Ensure Docker is not installed on a multi-user host without controls")},
		},

		// ---- Secrets (SEC) ----
		{
			ID: "SEC001", Group: model.GroupSecrets,
			Title:     "Plaintext secret in Compose configuration",
			Severity:  model.SeverityWarning,
			Rationale: "Secrets written directly into compose environment values end up in the file, in `docker inspect`, in process listings, and often in version control. Use Docker secrets or mounted secret files instead.",
			Controls:  []model.ControlRef{cAuthInfo, cConfig, cLogical},
		},
		{
			ID: "SEC002", Group: model.GroupSecrets,
			Title:     "Committed .env file containing secrets",
			Severity:  model.SeverityCritical,
			Rationale: "A .env file with secrets is tracked in git, so the secret is in history forever and exposed to anyone with repository access. Rotate it and remove it from version control.",
			Controls:  []model.ControlRef{cAuthInfo, cLogical},
		},
		{
			ID: "SEC003", Group: model.GroupSecrets,
			Title:     "Weak or default password",
			Severity:  model.SeverityCritical,
			Rationale: "A weak, empty, or well-known default password for a service is equivalent to no authentication — it is brute-forced or guessed in seconds.",
			Controls:  []model.ControlRef{cAuthInfo, cSecureAuth},
		},
		{
			ID: "SEC004", Group: model.GroupSecrets,
			Title:     "Secret passed via environment variable",
			Severity:  model.SeverityInfo,
			Rationale: "Environment variables holding secrets are visible to anyone who can inspect the container and are easy to leak in logs. Prefer Docker secrets or mounted files.",
			Controls:  []model.ControlRef{cAuthInfo, cConfig},
		},

		// ---- TLS / certificates (TLS) ----
		{
			ID: "TLS001", Group: model.GroupTLS,
			Title:     "Public service without HTTPS",
			Severity:  model.SeverityWarning,
			Rationale: "A public HTTP service transmits everything in cleartext. Terminate TLS at the reverse proxy and redirect HTTP to HTTPS.",
			Controls:  []model.ControlRef{cTransit, cCrypto},
		},
		{
			ID: "TLS002", Group: model.GroupTLS,
			Title:     "Expired TLS certificate on public endpoint",
			Severity:  model.SeverityCritical,
			Rationale: "An expired certificate breaks trust for every client and is a sign that automated renewal has failed — often the prelude to an outage or a downgrade attack.",
			Controls:  []model.ControlRef{cTransit, cCrypto},
		},
		{
			ID: "TLS003", Group: model.GroupTLS,
			Title:     "Self-signed certificate on public endpoint",
			Severity:  model.SeverityWarning,
			Rationale: "A self-signed certificate on a public endpoint trains users to click through warnings and provides no protection against active interception. Use a CA-issued certificate (e.g. Let's Encrypt).",
			Controls:  []model.ControlRef{cTransit, cCrypto},
		},
		{
			ID: "TLS004", Group: model.GroupTLS,
			Title:     "Weak TLS version or cipher suite",
			Severity:  model.SeverityWarning,
			Rationale: "Obsolete TLS versions (1.0/1.1) or weak ciphers are vulnerable to known downgrade and decryption attacks and fail most compliance baselines.",
			Controls:  []model.ControlRef{cTransit, cCrypto},
		},

		// ---- DNS (DNS) ----
		{
			ID: "DNS001", Group: model.GroupDNS,
			Title:     "Wildcard DNS record pointing at the host",
			Severity:  model.SeverityInfo,
			Rationale: "A wildcard record means every conceivable subdomain resolves to this host, making it easy to expose a new service unintentionally and harder to reason about your attack surface.",
			Controls:  []model.ControlRef{cNetSec, cConfig},
		},
		{
			ID: "DNS002", Group: model.GroupDNS,
			Title:     "Dangling DNS record (subdomain takeover risk)",
			Severity:  model.SeverityWarning,
			Rationale: "A DNS record points at a target that no longer resolves or is unclaimed. An attacker who claims that target can serve content from your domain — phishing, cookie theft, or full subdomain takeover.",
			Controls:  []model.ControlRef{cNetSec, cVulnMgmt},
		},

		// ---- Authentication / access (AUTH) ----
		{
			ID: "AUTH001", Group: model.GroupAuth,
			Title:     "Public service with no authentication layer",
			Severity:  model.SeverityWarning,
			Rationale: "A service is exposed publicly with no identity-aware proxy (Authelia/Authentik) or built-in auth in front of it. Forward authentication closes the gap for tools that ship with weak or no access control.",
			Controls:  []model.ControlRef{cLogical, cSecureAuth},
		},
		{
			ID: "AUTH002", Group: model.GroupAuth,
			Title:     "Default admin credentials for a well-known image",
			Severity:  model.SeverityCritical,
			Rationale: "A well-known image is configured with its documented default admin credentials. These are the first thing an attacker tries and are published in the project's own docs.",
			Controls:  []model.ControlRef{cLogical, cAuthInfo, cSecureAuth},
		},

		// ---- Supply chain (SUP) ----
		{
			ID: "SUP001", Group: model.GroupSupplyChain,
			Title:     "Image not pinned to a digest",
			Severity:  model.SeverityInfo,
			Rationale: "Without an @sha256 digest the exact image contents are not guaranteed, so a compromised or republished tag can change what runs without any change to your Compose file.",
			Controls:  []model.ControlRef{cMalicious, cVulnMgmt, cConfig, cis("4.5", "Content trust enabled")},
		},
		{
			ID: "SUP002", Group: model.GroupSupplyChain,
			Title:     "Image on the known-compromised feed",
			Severity:  model.SeverityCritical,
			Rationale: "The image (or a tag of it) appears on a feed of known-compromised or malicious images. Running it risks executing attacker-controlled code.",
			Controls:  []model.ControlRef{cMalicious, cVulnMgmt},
		},
		{
			ID: "SUP003", Group: model.GroupSupplyChain,
			Title:      "Image affected by a known-exploited CVE (CISA KEV)",
			Severity:   model.SeverityCritical,
			BaseImpact: 9.0,
			Rationale:  "A running image maps to a CVE on the CISA Known Exploited Vulnerabilities catalog — a vulnerability with confirmed, in-the-wild exploitation. When the affected service is reachable from a routable network this is the single strongest 'patch now' signal Keelix produces and caps the box RED. Image→CVE mapping is best-effort over the curated well-known self-hoster image set; absence of a finding is not a clean bill of health.",
			Controls:   []model.ControlRef{cVulnMgmt, cVulnDetect, cis("4.5", "Content trust enabled")},
		},
		{
			ID: "SUP004", Group: model.GroupSupplyChain,
			Title:      "Image affected by a high-EPSS CVE",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.0,
			Rationale:  "A running image maps to a CVE with a high FIRST.org EPSS exploit-prediction percentile (>= 0.90) that is not on the CISA KEV catalog. EPSS estimates the probability of exploitation in the next 30 days; a high percentile is a 'patch soon' nudge that has not yet crossed into confirmed exploitation. Image→CVE mapping is best-effort over the curated well-known self-hoster image set.",
			Controls:   []model.ControlRef{cVulnMgmt, cVulnDetect},
		},

		// ---- Service Configuration (SVC) ----
		{
			ID: "SVC001", Group: model.GroupService,
			Title:      "Redis has no authentication (no-auth triad)",
			Severity:   model.SeverityCritical,
			BaseImpact: 9.0,
			Rationale:  "Redis is running without a password (requirepass not set), with protected-mode disabled, and bound to a non-loopback address. This triad means any host that can reach the Redis port can read, write, and delete every key in the store without any credential. Redis stores session tokens, application cache, and often entire database snapshots; unauthenticated access is a direct path to data exfiltration and cache poisoning.",
			Controls:   []model.ControlRef{cLogical, cAuthInfo, cBoundary, cConfig},
		},
		{
			ID: "SVC002", Group: model.GroupService,
			Title:      "MongoDB authentication disabled",
			Severity:   model.SeverityCritical,
			BaseImpact: 9.0,
			Rationale:  "The MongoDB configuration does not set security.authorization: enabled, so the database accepts any connection without credentials. A default or misconfigured MongoDB instance is one of the most common sources of cloud data breaches; attackers actively scan for open MongoDB ports and exfiltrate or ransom the data within minutes of exposure.",
			Controls:   []model.ControlRef{cLogical, cAuthInfo, cBoundary},
		},
		{
			ID: "SVC003", Group: model.GroupService,
			Title:      "PostgreSQL pg_hba.conf allows trust auth for non-local hosts",
			Severity:   model.SeverityCritical,
			BaseImpact: 9.0,
			Rationale:  "The PostgreSQL client authentication configuration (pg_hba.conf) contains a 'trust' entry for a non-local host range, meaning PostgreSQL grants access to any connection from that range with no password check. Trust auth should never be used for non-loopback connections; any host matching the rule can connect as any database user, including the superuser.",
			Controls:   []model.ControlRef{cLogical, cAuthInfo, cBoundary},
		},
		{
			ID: "SVC004", Group: model.GroupService,
			Title:      "Elasticsearch X-Pack security disabled",
			Severity:   model.SeverityCritical,
			BaseImpact: 8.5,
			Rationale:  "Elasticsearch is configured with xpack.security.enabled: false, disabling authentication, TLS, and role-based access control for the entire cluster. Without X-Pack security, any client that can reach port 9200 can read, index, and delete all data across all indices, and can modify cluster settings.",
			Controls:   []model.ControlRef{cLogical, cAuthInfo, cBoundary, cConfig},
		},
		{
			ID: "SVC010", Group: model.GroupService,
			Title:      "*arr application (Sonarr/Radarr/Prowlarr/Lidarr/Readarr) authentication disabled",
			Severity:   model.SeverityCritical,
			BaseImpact: 7.5,
			Rationale:  "The *arr media-management application (Sonarr, Radarr, Prowlarr, Lidarr, or Readarr) has AuthenticationMethod set to None in its config.xml. With no authentication, anyone who can reach the web UI can control indexers, download clients, and library settings, and can read the application's API key which may have further integrations.",
			Controls:   []model.ControlRef{cLogical, cSecureAuth, cConfig},
		},
		{
			ID: "SVC011", Group: model.GroupService,
			Title:      "qBittorrent WebUI authentication disabled",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.0,
			Rationale:  "qBittorrent's WebUI is configured with authentication turned off. An unauthenticated WebUI allows anyone who can reach the port to add or remove torrents, change the download path to any host directory the process can write, and execute WebUI plugins — effectively arbitrary file-write on the host.",
			Controls:   []model.ControlRef{cLogical, cSecureAuth, cConfig},
		},
		{
			ID: "SVC020", Group: model.GroupService,
			Title:      "Grafana anonymous access enabled or default admin credentials",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.5,
			Rationale:  "Grafana is configured with anonymous access enabled (auth.anonymous.enabled = true) or the admin password has not been changed from the well-known default ('admin'). Anonymous access leaks every dashboard, data-source URL, and potentially embedded credentials. Default admin credentials let anyone take full administrative control of the Grafana instance.",
			Controls:   []model.ControlRef{cLogical, cAuthInfo, cSecureAuth},
		},
		{
			ID: "SVC021", Group: model.GroupService,
			Title:      "Prometheus/Loki has no authentication configured",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.5,
			Rationale:  "The Prometheus or Loki configuration does not define any authentication (basic_auth, bearer_token, or TLS client cert). Without authentication, anyone who can reach the metrics or log endpoint can read all scraped metrics and logs, which commonly contain hostnames, IP addresses, error traces, and operational secrets.",
			Controls:   []model.ControlRef{cLogical, cSecureAuth, cConfig},
		},
		{
			ID: "SVC030", Group: model.GroupService,
			Title:      "Vaultwarden admin token absent or weak",
			Severity:   model.SeverityCritical,
			BaseImpact: 8.0,
			Rationale:  "The Vaultwarden password manager is running without an ADMIN_TOKEN set, or with a token that is not an Argon2 hash and is shorter than the recommended minimum. Without a strong admin token the /admin panel is either open to anyone or protected only by a weak secret that is trivially brute-forced. The admin panel can reset user vaults, invite arbitrary users, and export all stored passwords.",
			Controls:   []model.ControlRef{cLogical, cAuthInfo, cSecureAuth, cConfig},
		},
		{
			ID: "SVC031", Group: model.GroupService,
			Title:      "Gitea installation not locked or open registration enabled",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.5,
			Rationale:  "The Gitea git server has INSTALL_LOCK set to false (the install wizard is accessible and can be used to overwrite the admin account) or open registration is enabled (anyone can create an account and access repositories). Both states allow an unauthenticated attacker to gain administrative or contributor access to hosted repositories.",
			Controls:   []model.ControlRef{cLogical, cSecureAuth, cConfig},
		},
		{
			ID: "SVC032", Group: model.GroupService,
			Title:      "Jenkins security disabled",
			Severity:   model.SeverityCritical,
			BaseImpact: 8.0,
			Rationale:  "The Jenkins CI/CD server has useSecurity set to false in its configuration, meaning the entire UI and API are accessible without any authentication or authorization. An unauthenticated user can create and run arbitrary pipelines, read build logs containing secrets, and execute code on the Jenkins controller and all connected agents.",
			Controls:   []model.ControlRef{cLogical, cSecureAuth, cBoundary, cConfig},
		},
		{
			ID: "SVC040", Group: model.GroupService,
			Title:      "Samba share with guest access enabled",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.0,
			Rationale:  "One or more Samba shares have 'guest ok = yes' set, allowing unauthenticated access to the share contents. Guest-readable shares expose files to anyone who can reach SMB port 445, including lateral-movement pivots within the LAN. Guest-writable shares allow arbitrary file upload.",
			Controls:   []model.ControlRef{cLogical, cAuthInfo, cNetSec},
		},
		{
			ID: "SVC041", Group: model.GroupService,
			Title:      "NFS export with no_root_squash or world-accessible",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.5,
			Rationale:  "An NFS export in /etc/exports uses no_root_squash (root on the client is treated as root on the server, bypassing the NFS security boundary) or exports to the world (*). Either condition allows a client with root access to read and overwrite any file on the exported filesystem as root, including SSH authorized_keys or sudoers.",
			Controls:   []model.ControlRef{cPrivAccess, cNetSec, cConfig},
		},
		{
			ID: "SVC050", Group: model.GroupService,
			Title:      "MinIO running with default root credentials",
			Severity:   model.SeverityCritical,
			BaseImpact: 8.0,
			Rationale:  "The MinIO object storage server is configured with the well-known default root credentials (MINIO_ROOT_USER=minioadmin / MINIO_ROOT_PASSWORD=minioadmin). Anyone who can reach the MinIO API or console can authenticate as the root user and read, overwrite, or delete all buckets and objects.",
			Controls:   []model.ControlRef{cLogical, cAuthInfo, cBoundary},
		},
		{
			ID: "SVC051", Group: model.GroupService,
			Title:      "Mosquitto MQTT broker allows anonymous connections",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.0,
			Rationale:  "The Mosquitto MQTT broker is configured with allow_anonymous true, permitting any client to connect, publish, and subscribe to all topics without credentials. In IoT and home-automation environments this exposes every device topic to eavesdropping and command injection.",
			Controls:   []model.ControlRef{cLogical, cSecureAuth, cNetSec},
		},
		{
			ID: "SVC052", Group: model.GroupService,
			Title:      "Syncthing GUI has no authentication",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.5,
			Rationale:  "The Syncthing graphical interface is configured without a username and password. Anyone who can reach the GUI port can add or remove sync folders, read the contents of synced paths, and connect the instance to an attacker-controlled device.",
			Controls:   []model.ControlRef{cLogical, cSecureAuth, cConfig},
		},
		{
			ID: "SVC060", Group: model.GroupService,
			Title:      "Traefik API/dashboard exposed insecurely (api.insecure=true)",
			Severity:   model.SeverityCritical,
			BaseImpact: 7.5,
			Rationale:  "Traefik is configured with api.insecure: true, which enables the dashboard and REST API on port 8080 without any authentication. The Traefik API provides a live map of every routed service, their TLS certificates, and middleware configuration, and in some versions can be used to modify routing rules at runtime.",
			Controls:   []model.ControlRef{cLogical, cBoundary, cConfig},
		},

		// ---- AI Agent Posture (AGT) ----
		{
			ID: "AGT001", Group: model.GroupAIAgent,
			Title:      "Agent auto-approval enabled",
			Severity:   model.SeverityCritical,
			BaseImpact: 8.5,
			Rationale:  "The AI agent is configured to execute shell commands, file writes, or tool calls without asking for human approval. A single prompt-injection or misconfigured task can run arbitrary commands on the host without any confirmation gate, turning the agent into an unauthenticated local code-execution surface.",
			Controls:   []model.ControlRef{cLogical, cMalicious, cConfig},
		},
		{
			ID: "AGT002", Group: model.GroupAIAgent,
			Title:      "Lethal-trifecta capability co-presence",
			Severity:   model.SeverityCritical,
			BaseImpact: 9.5,
			Rationale:  "A single agent process simultaneously has access to private data (broad filesystem or token access), an untrusted ingest channel (web browsing, search, or an external MCP server), and an exfil channel (a messaging or HTTP MCP server). Any one leg is a risk; all three together mean a prompt-injection in fetched content can read private data and exfiltrate it without any human approval step.",
			Controls:   []model.ControlRef{cLogical, cMalicious, cBoundary},
		},
		{
			ID: "AGT003", Group: model.GroupAIAgent,
			Title:      "Blast radius: admin or docker group membership",
			Severity:   model.SeverityWarning,
			BaseImpact: 7.0,
			Rationale:  "The agent process runs as a user who is a member of a privileged OS group (admin, wheel, sudo, or docker). If the agent is compromised or misused, it can escalate to full host control — sudo/wheel without a password prompt, or docker membership equivalent to root via a container escape.",
			Controls:   []model.ControlRef{cPrivAccess, cConfig},
		},
		{
			ID: "AGT004", Group: model.GroupAIAgent,
			Title:      "Credential file permissions too open",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.0,
			Rationale:  "An agent token or credential dotfile has file permissions wider than 0600, allowing other users on the system to read the credential. On a shared host, any local user can then impersonate the agent or call the API on the owner's behalf.",
			Controls:   []model.ControlRef{cAuthInfo, cConfig},
		},
		{
			ID: "AGT005", Group: model.GroupAIAgent,
			Title:      "Credential backup sprawl",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.0,
			Rationale:  "Backup copies of agent credential or config files (e.g. *.bak, *.orig, or files in a backup-tool snapshot) have been detected. Backup files often miss the access-control hardening applied to the originals, creating a secondary path to the same secrets.",
			Controls:   []model.ControlRef{cAuthInfo, cConfig, cVulnMgmt},
		},
		{
			ID: "AGT006", Group: model.GroupAIAgent,
			Title:      "Agent control surface bound to non-loopback address",
			Severity:   model.SeverityCritical,
			BaseImpact: 9.0,
			Rationale:  "An agent gateway or API socket is listening on an address that is reachable beyond the local machine (not 127.0.0.1 or ::1). Without authentication, any host that can reach the bind address can issue commands to the agent, read its context, or trigger autonomous actions — equivalent to an unauthenticated RCE on the network.",
			Controls:   []model.ControlRef{cBoundary, cLogical, cNetSec},
		},
		{
			ID: "AGT007", Group: model.GroupAIAgent,
			Title:      "Unattended autonomy: cron or keep-alive with auto-approval",
			Severity:   model.SeverityCritical,
			BaseImpact: 8.0,
			Rationale:  "A scheduled or keep-alive agent job is enabled while the agent's approval mode is also set to auto (no human confirmation required). This combination means the agent runs unattended commands indefinitely with no approval gate, amplifying any prompt-injection or misconfiguration into a persistent automated threat.",
			Controls:   []model.ControlRef{cLogical, cMalicious, cMonitor},
		},
		{
			ID: "AGT008", Group: model.GroupAIAgent,
			Title:      "Whole-disk or home-directory filesystem access",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.5,
			Rationale:  "The agent is configured with access to the entire filesystem or the user's home directory rather than a restricted workspace. A prompt-injection or errant task can read SSH keys, cloud credentials, browser cookies, and other secrets beyond the agent's intended working scope.",
			Controls:   []model.ControlRef{cPrivAccess, cConfig, cLogical},
		},
		{
			ID: "AGT009", Group: model.GroupAIAgent,
			Title:      "Untrusted inbound channel open to public",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.0,
			Rationale:  "The agent accepts instructions from a public or open channel (e.g. Discord group policy open, Telegram DM policy open). Any external actor can send the agent arbitrary tasks, bypassing the local trust boundary and enabling remote prompt-injection attacks.",
			Controls:   []model.ControlRef{cLogical, cBoundary, cMalicious},
		},
		{
			ID: "AGT010", Group: model.GroupAIAgent,
			Title:      "Unpinned agent skills, plugins, or extensions",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.5,
			Rationale:  "Agent extensions or skill packages are loaded from an unpinned source (no version tag, floating git ref, or non-official marketplace). An update to the upstream source can silently change the agent's behavior or inject malicious capability without any change to the local configuration.",
			Controls:   []model.ControlRef{cMalicious, cVulnMgmt, cConfig},
		},
		// ---- MCP Posture (MCP) ----
		{
			ID: "MCP001", Group: model.GroupMCP,
			Title:      "Plaintext secret in MCP server configuration",
			Severity:   model.SeverityCritical,
			BaseImpact: 8.0,
			Rationale:  "An MCP server's environment variable, HTTP header, or URL in the config file contains a secret-shaped value (API key, token, or password) stored in plaintext. Anyone who can read the config file — or any process with access to the environment — can extract and reuse the credential without any additional privilege.",
			Controls:   []model.ControlRef{cAuthInfo, cConfig, cLogical},
		},
		{
			ID: "MCP002", Group: model.GroupMCP,
			Title:      "MCP config file has weak permissions",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.5,
			Rationale:  "An MCP configuration file that may contain secrets (API keys, tokens, URLs with credentials) has file permissions wider than 0600. Other local users can read the file and extract any credentials it contains.",
			Controls:   []model.ControlRef{cAuthInfo, cConfig},
		},
		{
			ID: "MCP003", Group: model.GroupMCP,
			Title:      "Unpinned 'latest' MCP server via npx/uvx/pipx",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.0,
			Rationale:  "An MCP server is launched via npx, uvx, or pipx without pinning to a specific version, and the -y/--yes flag suppresses confirmation. The next time the agent starts, a silently updated package could introduce malicious tool definitions or change server behavior — a supply-chain attack vector with no local change.",
			Controls:   []model.ControlRef{cMalicious, cVulnMgmt, cConfig},
		},
		{
			ID: "MCP004", Group: model.GroupMCP,
			Title:      "HTTP/SSE MCP server bound non-loopback without authentication",
			Severity:   model.SeverityCritical,
			BaseImpact: 9.0,
			Rationale:  "An MCP server is listening on an HTTP or SSE transport at an address reachable beyond the local machine, with no authentication requirement detected. Any host that can reach the bind address can invoke MCP tools — including file system, shell, or external API tools — without any credentials.",
			Controls:   []model.ControlRef{cBoundary, cLogical, cNetSec},
		},
		{
			ID: "MCP005", Group: model.GroupMCP,
			Title:      "Localhost HTTP/SSE MCP on potentially vulnerable SDK version",
			Severity:   model.SeverityCritical,
			BaseImpact: 7.5,
			Rationale:  "An MCP server is configured to use the HTTP or SSE transport on localhost. Known vulnerabilities in early MCP SDK versions (Python < 1.23.0, TypeScript < 1.24.0) affect this transport. SDK-version verification from lockfiles is pending; this finding flags the transport type for manual review until version-precise detection is available.",
			Controls:   []model.ControlRef{cVulnMgmt, cSecureAuth, cConfig},
		},
		{
			ID: "MCP006", Group: model.GroupMCP,
			Title:      "MCP server from unvetted provenance",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.5,
			Rationale:  "The MCP server's resolved source (git remote or package registry) is an individual GitHub account or unverified origin rather than a recognized organization or official registry. Unvetted packages can be abandoned, typosquatted, or silently modified by the publisher without triggering any local alert.",
			Controls:   []model.ControlRef{cMalicious, cVulnMgmt},
		},
		{
			ID: "MCP007", Group: model.GroupMCP,
			Title:      "Tool-poisoning / rug-pull drift detected",
			Severity:   model.SeverityCritical,
			BaseImpact: 9.0,
			Rationale:  "An MCP server's tool descriptions have changed since the last verified baseline. A change in tool descriptions while the server identity (command or URL) is unchanged is the signature of a rug-pull or tool-poisoning attack — the server now does something different than what was originally reviewed and approved.",
			Controls:   []model.ControlRef{cMalicious, cVulnDetect, cMonitor},
		},
		{
			ID: "MCP008", Group: model.GroupMCP,
			Title:      "Permission-bypass amplifier present in MCP client config",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.0,
			Rationale:  "The MCP client configuration enables one or more permission-bypass settings (bypassPermissionsModeEnabled, allowAllBrowserActions, or broad trustedFolders). These settings amplify the impact of any other capability finding — an agent or MCP server that can already do something risky faces no additional confirmation gate.",
			Controls:   []model.ControlRef{cLogical, cConfig, cMalicious},
		},
		{
			ID: "MCP009", Group: model.GroupMCP,
			Title:      "Known-CVE MCP tooling detected",
			Severity:   model.SeverityCritical,
			BaseImpact: 8.5,
			Rationale:  "A running process or installed package matches a known-vulnerable MCP tool (e.g. MCP Inspector affected by CVE-2025-49596). These tools have documented exploits; using them in a development or agent environment exposes the host to the published attack vector.",
			Controls:   []model.ControlRef{cVulnMgmt, cVulnDetect, cMalicious},
		},
		// ---- Host OS Posture (HST) — SSH ----
		{
			ID: "HST001", Group: model.GroupHost,
			Title:      "SSH password authentication enabled",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.5,
			Rationale:  "When PasswordAuthentication is set to yes, any account with a weak or reused password is exposed to brute-force and credential-stuffing attacks over SSH. Disabling password auth and requiring public-key authentication eliminates this entire attack class. Most internet-facing SSH brute-force attempts rely solely on password guessing.",
			Controls: []model.ControlRef{
				cisl("5.1.1", "Ensure permissions on /etc/ssh/sshd_config are configured"),
				cisl("5.2.11", "Ensure SSH PasswordAuthentication is disabled"),
				soc2("CC6.1", "Logical access controls"),
				iso("A.8.5", "Secure authentication"),
			},
		},
		{
			ID: "HST002", Group: model.GroupHost,
			Title:      "SSH root login permitted",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.0,
			Rationale:  "Allowing root to authenticate directly over SSH removes the audit trail provided by sudo (no intermediate account to log), and a successful brute-force or credential-compromise immediately yields full host control. Setting PermitRootLogin to no or without-password forces all administrative actions through a named, auditable user. The prohibit-password setting still allows key-based root login and is treated as a finding because it retains the direct-root attack surface.",
			Controls: []model.ControlRef{
				cisl("5.2.10", "Ensure SSH root login is disabled"),
				soc2("CC6.1", "Logical access controls"),
				iso("A.8.2", "Privileged access rights"),
			},
		},
		{
			ID: "HST003", Group: model.GroupHost,
			Title:      "SSH internet-exposed with password auth and root login",
			Severity:   model.SeverityCritical,
			BaseImpact: 8.5,
			Rationale:  "The SSH daemon is simultaneously accepting password authentication, permitting direct root login, and bound to a non-loopback interface reachable from the internet. This trifecta means a successful brute-force or credential-stuffing attack grants immediate, unauthenticated root shell access to the host. This is the single most commonly exploited configuration in internet-facing Linux hosts and justifies an overall RED cap on the scan.",
			Controls: []model.ControlRef{
				cisl("5.2.10", "Ensure SSH root login is disabled"),
				cisl("5.2.11", "Ensure SSH PasswordAuthentication is disabled"),
				soc2("CC6.6", "Boundary protection / external threats"),
				iso("A.8.5", "Secure authentication"),
				iso("A.8.2", "Privileged access rights"),
			},
		},
		{
			ID: "HST004", Group: model.GroupHost,
			Title:      "SSH weak protocol parameters",
			Severity:   model.SeverityInfo,
			BaseImpact: 3.0,
			Rationale:  "One or more SSH daemon settings deviate from hardened defaults: MaxAuthTries above 4 allows more brute-force attempts per connection; LoginGraceTime above 60 seconds extends the window for incomplete handshakes; X11Forwarding enabled can be used to relay X11 traffic for session hijacking; PermitEmptyPasswords yes allows accounts with blank passwords to authenticate. Each individually is low-risk but together they widen the attack surface unnecessarily.",
			Controls: []model.ControlRef{
				cisl("5.2.5", "Ensure SSH MaxAuthTries is set to 4 or less"),
				cisl("5.2.14", "Ensure SSH LoginGraceTime is set to one minute or less"),
				cisl("5.2.6", "Ensure SSH X11 forwarding is disabled"),
				soc2("CC6.1", "Logical access controls"),
				iso("A.8.5", "Secure authentication"),
			},
		},

		// ---- Host OS Posture (HST) — Brute-force protection ----
		{
			ID: "HST005", Group: model.GroupHost,
			Title:      "No brute-force protection configured",
			Severity:   model.SeverityInfo,
			BaseImpact: 2.5,
			Rationale:  "Neither fail2ban nor a comparable intrusion-prevention tool is running and SSH password authentication is enabled. Without rate-limiting on failed authentication attempts, the host is susceptible to unthrottled brute-force attacks. Even modest tooling significantly raises the cost of credential-guessing campaigns.",
			Controls: []model.ControlRef{
				cisl("5.3.2", "Ensure lockout for failed password attempts is configured"),
				soc2("CC6.1", "Logical access controls"),
				iso("A.8.5", "Secure authentication"),
			},
		},

		// ---- Host OS Posture (HST) — Patch management ----
		{
			ID: "HST010", Group: model.GroupHost,
			Title:      "Security updates pending",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.0,
			Rationale:  "One or more packages with known security fixes are available but not yet installed. Unpatched software is the most common initial access vector in real-world breaches; the longer patches are delayed, the higher the probability that an exploit becomes available before the fix is applied. Hosts with more than 20 pending security updates or an end-of-life distro are elevated to Critical.",
			Controls: []model.ControlRef{
				cisl("1.2.2.1", "Ensure package manager repositories are configured"),
				soc2("CC7.1", "Vulnerability detection"),
				iso("A.8.8", "Management of technical vulnerabilities"),
			},
		},
		{
			ID: "HST011", Group: model.GroupHost,
			Title:      "Operating system has reached end of life",
			Severity:   model.SeverityCritical,
			BaseImpact: 7.0,
			Rationale:  "The host is running a Linux distribution version that has passed its vendor-published end-of-life date and no longer receives security updates. Any vulnerability discovered after EOL is permanently unpatched, meaning the risk profile only worsens over time. Migration to a supported release is the only remediation.",
			Controls: []model.ControlRef{
				cisl("1.1.1", "Ensure a supported version of the operating system is used"),
				soc2("CC7.1", "Vulnerability detection"),
				iso("A.8.8", "Management of technical vulnerabilities"),
			},
		},
		{
			ID: "HST012", Group: model.GroupHost,
			Title:      "Reboot required to apply kernel update",
			Severity:   model.SeverityInfo,
			BaseImpact: 2.5,
			Rationale:  "A kernel or libc update has been installed but the host has not been rebooted, so the running kernel is older than the installed one. The host may be missing kernel-level security patches until the next reboot. For live-patching environments this finding can be suppressed if kpatch or livepatch is active.",
			Controls: []model.ControlRef{
				cisl("1.2.2.1", "Ensure package manager repositories are configured"),
				soc2("CC7.1", "Vulnerability detection"),
				iso("A.8.8", "Management of technical vulnerabilities"),
			},
		},
		{
			ID: "HST013", Group: model.GroupHost,
			Title:      "Unattended upgrades not enabled",
			Severity:   model.SeverityInfo,
			BaseImpact: 2.5,
			Rationale:  "Automatic installation of security updates is not configured (apt unattended-upgrades or equivalent). Manual patching workflows introduce lag between vulnerability disclosure and remediation; automated security-only upgrades close this window without introducing instability from feature updates.",
			Controls: []model.ControlRef{
				cisl("1.2.2.1", "Ensure package manager repositories are configured"),
				soc2("CC7.1", "Vulnerability detection"),
				iso("A.8.8", "Management of technical vulnerabilities"),
			},
		},
		// ---- Host OS Posture (HST) — Accounts and privilege ----
		{
			ID: "HST020", Group: model.GroupHost,
			Title:      "Passwordless sudo rule present",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.0,
			Rationale:  "A NOPASSWD rule in /etc/sudoers or /etc/sudoers.d allows one or more users to run commands as root without supplying a password. Any process running as that user — including a compromised application — can escalate to root silently, with no password prompt to serve as a speed bump or logging event.",
			Controls: []model.ControlRef{
				cisl("5.2.2", "Ensure sudo commands use pty"),
				cisl("5.2.3", "Ensure sudo log file exists"),
				soc2("CC6.1", "Logical access controls"),
				iso("A.8.2", "Privileged access rights"),
			},
		},
		{
			ID: "HST021", Group: model.GroupHost,
			Title:      "Multiple accounts with UID 0",
			Severity:   model.SeverityCritical,
			BaseImpact: 7.5,
			Rationale:  "More than one account in /etc/passwd has UID 0, giving those accounts unconditional root privileges identical to the root account itself. Duplicate UID 0 accounts are a common persistence technique used by attackers after gaining initial access; their presence is highly anomalous on a correctly configured system and warrants immediate investigation.",
			Controls: []model.ControlRef{
				cisl("4.1.1", "Ensure password expiration is configured"),
				cisl("4.2.3", "Ensure all groups in /etc/passwd exist in /etc/group"),
				soc2("CC6.1", "Logical access controls"),
				iso("A.8.2", "Privileged access rights"),
			},
		},
		{
			ID: "HST022", Group: model.GroupHost,
			Title:      "Account with empty password detected",
			Severity:   model.SeverityCritical,
			BaseImpact: 7.5,
			Rationale:  "One or more local accounts in /etc/shadow have an empty password field, meaning authentication succeeds without any credential. An attacker with local network access or a shell session as any other user can switch to these accounts without being challenged. This finding requires root to read /etc/shadow; it returns NotAssessed when the collector lacked the necessary privilege.",
			Controls: []model.ControlRef{
				cisl("4.1.2", "Ensure minimum password age is configured"),
				cisl("4.4.3", "Ensure password hashing algorithm is SHA-512 or yescrypt"),
				soc2("CC6.1", "Logical access controls"),
				iso("A.5.17", "Authentication information"),
			},
		},
		{
			ID: "HST023", Group: model.GroupHost,
			Title:      "/etc/shadow is world-readable",
			Severity:   model.SeverityWarning,
			BaseImpact: 6.0,
			Rationale:  "The shadow password file has permissions that allow any local user to read it. Even with modern password hashing, world-readable shadow files enable offline cracking attacks and violate every OS security baseline. Correct permissions are 0000 (root-only) or 0640 (root:shadow).",
			Controls: []model.ControlRef{
				cisl("4.1.1", "Ensure password expiration is configured"),
				soc2("CC6.1", "Logical access controls"),
				iso("A.5.17", "Authentication information"),
			},
		},

		// ---- Host OS Posture (HST) — Firewall ----
		{
			ID: "HST030", Group: model.GroupHost,
			Title:      "Host firewall default inbound policy is not deny",
			Severity:   model.SeverityWarning,
			BaseImpact: 5.5,
			Rationale:  "The host firewall (nftables, iptables, or ufw) does not have a default-deny policy on inbound traffic, meaning any service that binds to a network interface is reachable unless an explicit deny rule exists. A default-deny stance is the correct posture: only whitelisted ports are accessible, and newly started services are blocked until explicitly permitted.",
			Controls: []model.ControlRef{
				cisl("3.4.1", "Ensure nftables is installed"),
				cisl("3.4.2", "Ensure a table exists for nftables"),
				soc2("CC6.6", "Boundary protection / external threats"),
				iso("A.8.20", "Network security"),
			},
		},

		// ---- Host OS Posture (HST) — Kernel hardening ----
		{
			ID: "HST040", Group: model.GroupHost,
			Title:      "Weak kernel sysctl hardening parameters",
			Severity:   model.SeverityInfo,
			BaseImpact: 3.0,
			Rationale:  "One or more kernel sysctl parameters deviate from the hardened baseline: kernel.randomize_va_space should be 2 (full ASLR); kernel.kptr_restrict should be at least 1 (hide kernel pointers from unprivileged users); kernel.dmesg_restrict should be 1 (hide dmesg from unprivileged users); kernel.yama.ptrace_scope should be at least 1 (restrict ptrace to parent processes); fs.suid_dumpable should be 0 (disable core dumps for setuid binaries). Each individually is low-risk but together they provide meaningful defense-in-depth against local privilege escalation.",
			Controls: []model.ControlRef{
				cisl("1.5.1", "Ensure address space layout randomization is enabled"),
				cisl("1.5.2", "Ensure ptrace_scope is restricted"),
				soc2("CC6.8", "Prevention of unauthorized/malicious software"),
				iso("A.8.9", "Configuration management"),
			},
		},

		// ---- Host OS Posture (HST) — Disk encryption ----
		{
			ID: "HST041", Group: model.GroupHost,
			Title:      "No disk encryption detected",
			Severity:   model.SeverityInfo,
			BaseImpact: 2.0,
			Rationale:  "No LUKS or dm-crypt encrypted block device was detected on the host. Without full-disk or volume-level encryption, physical or hypervisor-level access to the storage medium allows offline extraction of all data, including secrets, databases, and logs. This is an informational finding because cloud VMs typically rely on provider-managed encryption at rest; operators should verify the provider's default.",
			Controls: []model.ControlRef{
				cisl("1.3.1", "Ensure AIDE is installed"),
				soc2("CC6.7", "Data in transit encryption"),
				iso("A.8.24", "Use of cryptography"),
			},
		},
	}
	// fatalImpact is the explicit BaseImpact for the known fatal checks; these
	// are the bypass/exposure failures that justify an overall RED cap.
	// Rule: every SeverityCritical SVC/FW config check must be Fatal.
	fatalImpact := map[string]float64{
		"EXP001": 9.5, // sensitive datastore reachable from the internet
		"FW001":  9.5, // Docker bypasses the host firewall for a published port
		"FW005":  9.5, // Docker daemon API over TCP
		"FW006":  9.0, // k3s/kubelet anonymous authentication enabled
		"AGT002": 9.5, // lethal-trifecta: private data + untrusted ingest + exfil channel
		"AGT006": 9.0, // agent control surface bound to non-loopback address
		"MCP004": 9.0, // HTTP/SSE MCP bound non-loopback without authentication
		"HST003": 8.5, // SSH internet-exposed: password auth + root login + non-loopback bind
		"SVC001": 9.0, // Redis no-auth triad
		"SVC002": 9.0, // MongoDB no-auth
		"SVC003": 9.0, // PostgreSQL trust auth
		"SVC004": 8.5, // Elasticsearch X-Pack security disabled
		"SVC010": 8.0, // *arr application no-auth (R4-3: rule every SeverityCritical SVC/FW is Fatal)
		"SVC030": 8.5, // Vaultwarden admin token absent or weak
		"SVC032": 8.5, // Jenkins security disabled (no-auth → RCE)
		"SVC050": 8.5, // MinIO running with default root credentials
		"SVC060": 8.0, // Traefik api.insecure=true (R4-3: rule every SeverityCritical SVC/FW is Fatal)
		// SUP003 is NOT in fatalImpact: its BaseImpact 9.0 is set directly on
		// the Entry (SF-3). Fatal escalation is conditional: applyKEVFatal in
		// the score engine promotes a KEV finding to Fatal only when the
		// service's ExposureClass.CanCapRed() — i.e. LAN, Filtered, or
		// Internet. A KEV on a localhost-only service stays a high-weight
		// non-fatal contributor and never caps RED.
	}
	m := make(map[string]Entry, len(list))
	for _, e := range list {
		if _, dup := m[e.ID]; dup {
			panic("duplicate catalog entry: " + e.ID)
		}
		if e.BaseImpact == 0 {
			e.BaseImpact = defaultBaseImpact(e.Severity)
		}
		if bi, ok := fatalImpact[e.ID]; ok {
			e.Fatal = true
			e.BaseImpact = bi
		}
		m[e.ID] = e
	}
	return m
}()

// Get returns the catalog entry for an ID. It panics on an unknown ID because
// that indicates a programming error (a check referencing a non-existent entry).
func Get(id string) Entry {
	e, ok := entries[id]
	if !ok {
		panic("unknown catalog entry: " + id)
	}
	return e
}

// Has reports whether the catalog contains the given ID.
func Has(id string) bool {
	_, ok := entries[id]
	return ok
}

// All returns every catalog entry sorted by ID.
func All() []Entry {
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Finding returns a failing finding pre-filled from the catalog entry: CheckID,
// Group, Title, default Severity, Detail (the rationale), and Controls. Callers
// set Service/Resource/Evidence/Fix and may override Severity.
func (e Entry) Finding() model.Finding {
	return model.Finding{
		CheckID:    e.ID,
		Group:      e.Group,
		Title:      e.Title,
		Severity:   e.Severity,
		Detail:     e.Rationale,
		Controls:   append([]model.ControlRef(nil), e.Controls...),
		BaseImpact: e.BaseImpact,
		Fatal:      e.Fatal,
	}
}

// Pass returns a passing finding (SeverityOK, Passed=true) for this check,
// carrying the control mappings so the coverage matrix can show it as tested,
// and carrying BaseImpact so passing checks contribute to the v2 score
// denominator (preventing applicable-only normalization collapse).
// Fatal is intentionally left false: a Fatal pass must not trigger the RED cap.
func (e Entry) Pass(detail string) model.Finding {
	if detail == "" {
		detail = "No issues found for this check."
	}
	return model.Finding{
		CheckID:    e.ID,
		Group:      e.Group,
		Title:      e.Title,
		Severity:   model.SeverityOK,
		Passed:     true,
		Detail:     detail,
		Controls:   append([]model.ControlRef(nil), e.Controls...),
		BaseImpact: e.BaseImpact,
	}
}
