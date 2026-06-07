// Package intel is shared, deterministic reference data used by the check
// library: which ports belong to sensitive services, the documented default
// credentials of well-known images, common weak passwords, and which ports a
// given service is expected to expose. Keeping this data in one place ensures
// every check reasons about the same facts.
package intel

import "strings"

// PortCategory classifies why a port is sensitive.
type PortCategory string

const (
	CategoryDatastore PortCategory = "datastore"
	CategoryCache     PortCategory = "cache"
	CategoryBroker    PortCategory = "message-broker"
	CategoryAdmin     PortCategory = "admin"
	CategorySearch    PortCategory = "search"
	CategoryInfra     PortCategory = "infrastructure"
)

// PortInfo describes a well-known sensitive port.
type PortInfo struct {
	Port     int
	Service  string
	Category PortCategory
}

// sensitivePorts maps a TCP port to the internal-only service that owns it.
// These are services that should essentially never be reachable from the
// public internet.
var sensitivePorts = map[int]PortInfo{
	5432:  {5432, "PostgreSQL", CategoryDatastore},
	3306:  {3306, "MySQL/MariaDB", CategoryDatastore},
	27017: {27017, "MongoDB", CategoryDatastore},
	27018: {27018, "MongoDB (shard)", CategoryDatastore},
	5984:  {5984, "CouchDB", CategoryDatastore},
	7000:  {7000, "Cassandra (internode)", CategoryDatastore},
	9042:  {9042, "Cassandra (CQL)", CategoryDatastore},
	8086:  {8086, "InfluxDB", CategoryDatastore},
	6379:  {6379, "Redis", CategoryCache},
	11211: {11211, "Memcached", CategoryCache},
	9200:  {9200, "Elasticsearch", CategorySearch},
	9300:  {9300, "Elasticsearch (transport)", CategorySearch},
	7700:  {7700, "Meilisearch", CategorySearch},
	8108:  {8108, "Typesense", CategorySearch},
	5672:  {5672, "RabbitMQ (AMQP)", CategoryBroker},
	15672: {15672, "RabbitMQ (management)", CategoryAdmin},
	9092:  {9092, "Kafka", CategoryBroker},
	4222:  {4222, "NATS", CategoryBroker},
	1883:  {1883, "MQTT", CategoryBroker},
	2375:  {2375, "Docker daemon (unencrypted)", CategoryInfra},
	2376:  {2376, "Docker daemon (TLS)", CategoryInfra},
	2379:  {2379, "etcd (client)", CategoryInfra},
	2380:  {2380, "etcd (peer)", CategoryInfra},
	9000:  {9000, "MinIO / Portainer / PHP-FPM", CategoryAdmin},
	9001:  {9001, "MinIO console", CategoryAdmin},
	9090:  {9090, "Prometheus", CategoryAdmin},
	3000:  {3000, "Grafana / app dev server", CategoryAdmin},
	8080:  {8080, "HTTP admin / alt-http", CategoryAdmin},
	8081:  {8081, "Admin UI (alt)", CategoryAdmin},
	8090:  {8090, "Admin UI (alt)", CategoryAdmin},
	5601:  {5601, "Kibana", CategoryAdmin},
	8200:  {8200, "HashiCorp Vault", CategoryInfra},
	8500:  {8500, "Consul", CategoryInfra},
	2049:  {2049, "NFS", CategoryInfra},
	389:   {389, "LDAP", CategoryInfra},
	636:   {636, "LDAPS", CategoryInfra},
}

// LookupPort returns information about a sensitive port and whether it is known.
func LookupPort(port int) (PortInfo, bool) {
	p, ok := sensitivePorts[port]
	return p, ok
}

// IsSensitivePort reports whether the port belongs to a known internal-only service.
func IsSensitivePort(port int) bool {
	_, ok := sensitivePorts[port]
	return ok
}

// SensitivePorts returns a copy of all known sensitive ports.
func SensitivePorts() []PortInfo {
	out := make([]PortInfo, 0, len(sensitivePorts))
	for _, p := range sensitivePorts {
		out = append(out, p)
	}
	return out
}

// expectedPorts maps an image-name keyword to ports that are normal/expected to
// be public for that kind of service. Used for service-intent inference so the
// exposure checks do not flag a media server's web port as a surprise.
var expectedPorts = map[string][]int{
	"jellyfin":       {8096, 8920},
	"plex":           {32400},
	"emby":           {8096},
	"nginx":          {80, 443},
	"caddy":          {80, 443},
	"traefik":        {80, 443},
	"httpd":          {80, 443},
	"nextcloud":      {80, 443},
	"wordpress":      {80, 443},
	"ghost":          {2368, 80, 443},
	"gitea":          {3000, 22, 80, 443},
	"forgejo":        {3000, 22, 80, 443},
	"vaultwarden":    {80, 443},
	"jackett":        {9117},
	"sonarr":         {8989},
	"radarr":         {7878},
	"home-assistant": {8123},
	"homeassistant":  {8123},
	"pihole":         {80, 443, 53},
	"uptime-kuma":    {3001},
}

// ExpectedPublicPort reports whether the given port is an expected public port
// for the given image (intent inference). The image may include registry/tag.
func ExpectedPublicPort(image string, port int) bool {
	base := strings.ToLower(ImageBase(image))
	for keyword, ports := range expectedPorts {
		if strings.Contains(base, keyword) {
			for _, p := range ports {
				if p == port {
					return true
				}
			}
		}
	}
	// Standard web ports are generally intended to be public.
	return port == 80 || port == 443
}
