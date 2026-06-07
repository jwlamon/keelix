package model

// Stack is the parsed representation of a Docker Compose deployment plus the
// optional surrounding context (.env, reverse proxy config, firewall rules).
type Stack struct {
	// ComposePath is the path the compose file was read from.
	ComposePath string `json:"compose_path"`
	// ProjectName is the compose project name (dir name by default).
	ProjectName string `json:"project_name,omitempty"`
	// Services are the parsed services, in file order.
	Services []*Service `json:"services"`
	// Networks declared at the top level.
	Networks map[string]Network `json:"networks,omitempty"`
	// Volumes declared at the top level.
	Volumes map[string]Volume `json:"volumes,omitempty"`
	// Secrets declared at the top level (compose `secrets:`).
	Secrets map[string]Secret `json:"secrets,omitempty"`
	// Env holds values loaded from a .env file (used for interpolation + secret checks).
	Env map[string]string `json:"-"`
	// EnvPath is the path of the .env file that was loaded, if any.
	EnvPath string `json:"env_path,omitempty"`
	// EnvCommitted is true if a .env file was found tracked in git.
	EnvCommitted bool `json:"env_committed,omitempty"`
	// Proxy is the detected reverse-proxy configuration, if any.
	Proxy *ProxyConfig `json:"proxy,omitempty"`
	// Firewall is the parsed host firewall (UFW/iptables), if provided.
	Firewall *FirewallConfig `json:"firewall,omitempty"`
	// Raw is the full decoded compose document for checks that need rare fields.
	Raw map[string]any `json:"-"`
}

// Service returns the service with the given name, or nil.
func (s *Stack) Service(name string) *Service {
	for _, svc := range s.Services {
		if svc.Name == name {
			return svc
		}
	}
	return nil
}

// Service is a single compose service.
type Service struct {
	Name string `json:"name"`
	// Image is the raw image reference, e.g. "postgres:16" or "redis:latest".
	Image string `json:"image,omitempty"`
	// Build is the build context path if the service is built locally.
	Build string `json:"build,omitempty"`
	// Ports are the published port mappings.
	Ports []PortMapping `json:"ports,omitempty"`
	// Expose are container-internal exposed ports (not published to host).
	Expose []int `json:"expose,omitempty"`
	// Environment are environment variables (already interpolated where possible).
	Environment map[string]string `json:"environment,omitempty"`
	// EnvFile lists referenced env_file paths.
	EnvFile []string `json:"env_file,omitempty"`
	// Volumes are the mounted volumes/binds.
	Volumes []VolumeMount `json:"volumes,omitempty"`
	// CapAdd / CapDrop are Linux capability changes.
	CapAdd  []string `json:"cap_add,omitempty"`
	CapDrop []string `json:"cap_drop,omitempty"`
	// Privileged is true if the container runs privileged.
	Privileged bool `json:"privileged,omitempty"`
	// NetworkMode is e.g. "host", "bridge", "service:foo".
	NetworkMode string `json:"network_mode,omitempty"`
	// Networks the service is attached to.
	Networks []string `json:"networks,omitempty"`
	// User is the configured user (uid[:gid] or name); empty means image default (often root).
	User string `json:"user,omitempty"`
	// ReadOnly is true if read_only: true (read-only root filesystem).
	ReadOnly bool `json:"read_only,omitempty"`
	// SecurityOpt are security_opt entries (e.g. "no-new-privileges:true").
	SecurityOpt []string `json:"security_opt,omitempty"`
	// Restart policy.
	Restart string `json:"restart,omitempty"`
	// DependsOn service names.
	DependsOn []string `json:"depends_on,omitempty"`
	// Labels are the service labels (used to read Traefik/router config).
	Labels map[string]string `json:"labels,omitempty"`
	// Deploy carries resource limits (compose `deploy.resources`).
	Deploy *DeployConfig `json:"deploy,omitempty"`
	// Raw is the decoded service map for rare fields.
	Raw map[string]any `json:"-"`
}

// HasCap reports whether the service adds the given capability (case-insensitive,
// "ALL" matches anything).
func (s *Service) HasCap(cap string) bool {
	for _, c := range s.CapAdd {
		if equalFold(c, cap) || equalFold(c, "ALL") {
			return true
		}
	}
	return false
}

// MountsDockerSocket reports whether the service bind-mounts the docker socket.
func (s *Service) MountsDockerSocket() bool {
	for _, v := range s.Volumes {
		if v.Source == "/var/run/docker.sock" || v.Target == "/var/run/docker.sock" {
			return true
		}
	}
	return false
}

// RunsAsRoot returns true if the service has no explicit non-root user.
// This is a heuristic: empty User or User "0"/"root" => root.
func (s *Service) RunsAsRoot() bool {
	switch s.User {
	case "", "0", "root", "0:0":
		return true
	default:
		return false
	}
}

// PortMapping is a published host:container port mapping.
type PortMapping struct {
	// HostIP is the bind address ("" defaults to 0.0.0.0 = all interfaces).
	HostIP string `json:"host_ip,omitempty"`
	// HostPort is the published port on the host (0 if random/unset).
	HostPort int `json:"host_port"`
	// ContainerPort is the in-container port.
	ContainerPort int `json:"container_port"`
	// Protocol is "tcp" or "udp".
	Protocol string `json:"protocol"`
	// Raw is the original mapping string, e.g. "127.0.0.1:5432:5432".
	Raw string `json:"raw,omitempty"`
}

// PublishedToAllInterfaces reports whether this mapping is reachable on all host
// interfaces (no explicit 127.0.0.1 / loopback bind).
func (p PortMapping) PublishedToAllInterfaces() bool {
	switch p.HostIP {
	case "", "0.0.0.0", "::", "*":
		return true
	default:
		// Any non-loopback explicit IP is also externally bound.
		return !isLoopback(p.HostIP)
	}
}

// VolumeMount is a bind or named-volume mount.
type VolumeMount struct {
	Type     string `json:"type"` // "bind", "volume", "tmpfs"
	Source   string `json:"source,omitempty"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
	Raw      string `json:"raw,omitempty"`
}

// Network is a top-level compose network.
type Network struct {
	Name     string `json:"name,omitempty"`
	Driver   string `json:"driver,omitempty"`
	External bool   `json:"external,omitempty"`
	Internal bool   `json:"internal,omitempty"`
}

// Volume is a top-level compose volume.
type Volume struct {
	Name     string `json:"name,omitempty"`
	Driver   string `json:"driver,omitempty"`
	External bool   `json:"external,omitempty"`
}

// Secret is a top-level compose secret.
type Secret struct {
	Name        string `json:"name,omitempty"`
	File        string `json:"file,omitempty"`
	Environment string `json:"environment,omitempty"`
	External    bool   `json:"external,omitempty"`
}

// DeployConfig carries the resource-limit portion of compose `deploy`.
type DeployConfig struct {
	// HasLimits is true if any cpu/memory limit is set.
	HasLimits   bool   `json:"has_limits"`
	MemoryLimit string `json:"memory_limit,omitempty"`
	CPULimit    string `json:"cpu_limit,omitempty"`
}

// ProxyKind identifies the reverse-proxy implementation.
type ProxyKind string

const (
	ProxyTraefik ProxyKind = "traefik"
	ProxyCaddy   ProxyKind = "caddy"
	ProxyNginx   ProxyKind = "nginx"
	ProxyNPM     ProxyKind = "nginx-proxy-manager"
	ProxyUnknown ProxyKind = "unknown"
)

// ProxyConfig is the parsed reverse-proxy configuration.
type ProxyConfig struct {
	Kind ProxyKind `json:"kind"`
	// Path is the file or service the config was read from.
	Path string `json:"path,omitempty"`
	// DashboardExposed is true if an admin dashboard/API is exposed insecurely
	// (e.g. Traefik api.insecure=true).
	DashboardExposed bool `json:"dashboard_exposed,omitempty"`
	// Routes are the parsed routes the proxy serves.
	Routes []ProxyRoute `json:"routes,omitempty"`
	// Raw is the raw config text for fallback heuristics.
	Raw string `json:"-"`
}

// ProxyRoute is a single host/path route served by the proxy.
type ProxyRoute struct {
	// Host is the matched hostname, e.g. "app.example.com".
	Host string `json:"host,omitempty"`
	// PathPrefix is the matched path, if any.
	PathPrefix string `json:"path_prefix,omitempty"`
	// Service is the upstream service the route forwards to.
	Service string `json:"service,omitempty"`
	// TLS is true if the route terminates TLS.
	TLS bool `json:"tls"`
	// HasAuth is true if an auth middleware / basic-auth fronts the route.
	HasAuth bool `json:"has_auth"`
	// SecurityHeaders is true if security headers (HSTS etc.) are configured.
	SecurityHeaders bool `json:"security_headers"`
	// Wildcard is true for overly broad host rules.
	Wildcard bool `json:"wildcard,omitempty"`
}

// FirewallEngine identifies the host firewall the rules came from.
type FirewallEngine string

const (
	FirewallUFW      FirewallEngine = "ufw"
	FirewallIptables FirewallEngine = "iptables"
)

// FirewallConfig is the parsed host firewall state.
type FirewallConfig struct {
	Engine FirewallEngine `json:"engine"`
	Path   string         `json:"path,omitempty"`
	// DefaultIncoming is the default incoming policy ("deny"/"allow").
	DefaultIncoming string `json:"default_incoming,omitempty"`
	// Rules are the parsed allow/deny rules.
	Rules []FirewallRule `json:"rules,omitempty"`
	// HasDockerUserChain is true if a DOCKER-USER chain rule exists (the correct
	// way to actually restrict Docker-published ports).
	HasDockerUserChain bool   `json:"has_docker_user_chain,omitempty"`
	Raw                string `json:"-"`
}

// Denies reports whether the firewall claims to deny the given TCP port.
func (f *FirewallConfig) Denies(port int) bool {
	if f == nil {
		return false
	}
	for _, r := range f.Rules {
		if r.Port == port && r.Action == "deny" {
			return true
		}
	}
	return false
}

// FirewallRule is a single firewall rule.
type FirewallRule struct {
	Action   string `json:"action"` // "allow" / "deny"
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	From     string `json:"from,omitempty"`
	Raw      string `json:"raw,omitempty"`
}
