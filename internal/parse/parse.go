// Package parse turns a Docker Compose deployment (+ optional .env,
// reverse-proxy config, firewall rules) into a *model.Stack.
package parse

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

// Options controls how LoadStack operates.
type Options struct {
	ComposePath     string // optional; empty = whole-box scan with no compose stack
	EnvPath         string // optional; if empty, auto-detect a .env next to the compose file
	FirewallPath    string // optional UFW/iptables dump file
	ProxyConfigPath string // optional reverse-proxy config file (Caddyfile/nginx.conf/traefik.yml)
}

// inferProxyKindFromFilename infers a ProxyKind from a config filename.
// Filenames containing "caddy" map to ProxyCaddy, "traefik" to ProxyTraefik,
// and everything else defaults to ProxyNginx.
func inferProxyKindFromFilename(path string) model.ProxyKind {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(base, "caddy"):
		return model.ProxyCaddy
	case strings.Contains(base, "traefik"):
		return model.ProxyTraefik
	default:
		return model.ProxyNginx
	}
}

// LoadStack is the top-level entry point. It parses the compose file, loads and
// interpolates the .env, attaches a firewall config, and builds the proxy config.
func LoadStack(opts Options) (*model.Stack, error) {
	// Whole-box quickstart: with no compose file, start from an empty stack and
	// assess the box from inside-out signals. Firewall and proxy still load when
	// supplied via Options; the compose parse + .env interpolation only apply
	// when a compose file is given.
	if opts.ComposePath == "" {
		s := &model.Stack{}
		if opts.FirewallPath != "" {
			fw, err := LoadFirewall(opts.FirewallPath)
			if err != nil {
				return nil, fmt.Errorf("loading firewall: %w", err)
			}
			s.Firewall = fw
		}
		if opts.ProxyConfigPath != "" {
			// No compose services to detect the proxy kind from; infer from filename.
			kind := inferProxyKindFromFilename(opts.ProxyConfigPath)
			pc := &model.ProxyConfig{Kind: kind}
			enrichProxyFromFile(pc, opts.ProxyConfigPath)
			s.Proxy = pc
		}
		return s, nil
	}

	s, err := ParseCompose(opts.ComposePath)
	if err != nil {
		return nil, err
	}

	// Resolve .env path.
	envPath := opts.EnvPath
	if envPath == "" {
		candidate := filepath.Join(filepath.Dir(opts.ComposePath), ".env")
		if _, err2 := os.Stat(candidate); err2 == nil {
			envPath = candidate
		}
	}

	var env map[string]string
	if envPath != "" {
		env, err = LoadEnvFile(envPath)
		if err != nil {
			return nil, fmt.Errorf("loading env file: %w", err)
		}
		s.Env = env
		s.EnvPath = envPath
		s.EnvCommitted = isEnvCommitted(envPath)
	}

	// Interpolate compose string values using the loaded env.
	if env != nil {
		interpolateStack(s, env)
	}

	// Firewall.
	if opts.FirewallPath != "" {
		fw, err2 := LoadFirewall(opts.FirewallPath)
		if err2 != nil {
			return nil, fmt.Errorf("loading firewall: %w", err2)
		}
		s.Firewall = fw
	}

	// Proxy.
	proxy := ParseProxyFromStack(s)
	if proxy != nil && opts.ProxyConfigPath != "" {
		enrichProxyFromFile(proxy, opts.ProxyConfigPath)
	}
	s.Proxy = proxy

	return s, nil
}

// ParseCompose parses a Docker Compose file and returns a *model.Stack.
func ParseCompose(path string) (*model.Stack, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI argument; local CLI reading the user's own file
	if err != nil {
		return nil, fmt.Errorf("reading compose file: %w", err)
	}

	var raw map[string]any
	if err = yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing compose YAML: %w", err)
	}

	s := &model.Stack{
		ComposePath: path,
		ProjectName: filepath.Base(filepath.Dir(path)),
		Raw:         raw,
	}

	// Services.
	if svcMap, ok := raw["services"]; ok {
		s.Services = parseServices(svcMap)
	}

	// Top-level networks.
	if nets, ok := raw["networks"]; ok {
		s.Networks = parseTopNetworks(nets)
	}

	// Top-level volumes.
	if vols, ok := raw["volumes"]; ok {
		s.Volumes = parseTopVolumes(vols)
	}

	// Top-level secrets.
	if secrets, ok := raw["secrets"]; ok {
		s.Secrets = parseTopSecrets(secrets)
	}

	return s, nil
}

// LoadEnvFile parses a KEY=VALUE env file.
// Blank lines and #comments are ignored. Surrounding quotes are stripped.
// Supports `export KEY=VAL` syntax.
func LoadEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is an operator-supplied CLI argument; local CLI reading the user's own file
	if err != nil {
		return nil, fmt.Errorf("opening env file: %w", err)
	}
	defer f.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip optional `export ` prefix.
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimSpace(line)

		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			// Key with no value: set to empty.
			env[line] = ""
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := line[idx+1:]
		val = stripQuotes(val)
		env[key] = val
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	return env, nil
}

// LoadFirewall sniffs the format of a UFW/iptables dump and parses it.
func LoadFirewall(path string) (*model.FirewallConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI argument; local CLI reading the user's own file
	if err != nil {
		return nil, fmt.Errorf("reading firewall file: %w", err)
	}
	text := string(data)

	fw := &model.FirewallConfig{Path: path, Raw: text}

	if isUFW(text) {
		parseUFW(fw, text)
	} else {
		parseIptables(fw, text)
	}
	return fw, nil
}

// ParseProxyFromStack detects a reverse proxy service in the stack and builds
// a ProxyConfig from labels and commands. Returns nil if no proxy is detected.
func ParseProxyFromStack(s *model.Stack) *model.ProxyConfig {
	var proxySvc *model.Service
	var kind model.ProxyKind

	for _, svc := range s.Services {
		base := intel.ImageBase(svc.Image)
		switch {
		case strings.Contains(base, "traefik"):
			kind = model.ProxyTraefik
			proxySvc = svc
		case strings.Contains(base, "nginxproxymanager") || strings.Contains(base, "nginx-proxy-manager"):
			kind = model.ProxyNPM
			proxySvc = svc
		case strings.Contains(base, "caddy"):
			kind = model.ProxyCaddy
			proxySvc = svc
		case strings.Contains(base, "nginx"):
			kind = model.ProxyNginx
			proxySvc = svc
		}
		if proxySvc != nil {
			break
		}
	}

	if proxySvc == nil {
		return nil
	}

	pc := &model.ProxyConfig{Kind: kind}

	if kind == model.ProxyTraefik {
		parseTraefikProxy(s, proxySvc, pc)
	}

	return pc
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// parseServices converts the services map from raw YAML into []*model.Service.
func parseServices(raw any) []*model.Service {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	svcs := make([]*model.Service, 0, len(m))
	for name, val := range m {
		svcMap, ok := val.(map[string]any)
		if !ok {
			continue
		}
		svc := parseService(name, svcMap)
		svcs = append(svcs, svc)
	}
	return svcs
}

func parseService(name string, m map[string]any) *model.Service {
	svc := &model.Service{Name: name, Raw: m}

	svc.Image = toString(m["image"])

	// build: string or map{context:...}
	switch b := m["build"].(type) {
	case string:
		svc.Build = b
	case map[string]any:
		svc.Build = toString(b["context"])
	}

	// ports
	svc.Ports = parsePorts(m["ports"])

	// expose
	svc.Expose = parseExpose(m["expose"])

	// environment
	svc.Environment = parseEnvMap(m["environment"])

	// env_file
	svc.EnvFile = parseStringOrList(m["env_file"])

	// volumes
	svc.Volumes = parseVolumes(m["volumes"])

	// cap_add / cap_drop
	svc.CapAdd = parseStringList(m["cap_add"])
	svc.CapDrop = parseStringList(m["cap_drop"])

	// privileged
	svc.Privileged = toBool(m["privileged"])

	// network_mode
	svc.NetworkMode = toString(m["network_mode"])

	// networks: list or map -> keys
	svc.Networks = parseNetworkList(m["networks"])

	// user
	svc.User = toString(m["user"])

	// read_only
	svc.ReadOnly = toBool(m["read_only"])

	// security_opt
	svc.SecurityOpt = parseStringList(m["security_opt"])

	// restart
	svc.Restart = toString(m["restart"])

	// depends_on: list or map -> keys
	svc.DependsOn = parseDependsOn(m["depends_on"])

	// labels: map or list
	svc.Labels = parseLabels(m["labels"])

	// deploy resources
	svc.Deploy = parseDeployConfig(m["deploy"])

	return svc
}

// parsePorts handles both short string syntax and long-form list-of-maps.
func parsePorts(raw any) []model.PortMapping {
	if raw == nil {
		return nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []model.PortMapping
	for _, item := range items {
		switch v := item.(type) {
		case string:
			pm := parsePortString(v)
			out = append(out, pm)
		case map[string]any:
			pm := parsePortMap(v)
			out = append(out, pm)
		case int:
			pm := model.PortMapping{
				ContainerPort: v,
				Protocol:      "tcp",
				Raw:           strconv.Itoa(v),
			}
			out = append(out, pm)
		}
	}
	return out
}

// parsePortString parses short port syntax:
//
//	"5432"
//	"5432:5432"
//	"127.0.0.1:5432:5432"
//	"8080:80/udp"
//	"0.0.0.0:80:80"
func parsePortString(s string) model.PortMapping {
	pm := model.PortMapping{Protocol: "tcp", Raw: s}

	// Extract protocol suffix.
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		pm.Protocol = strings.ToLower(s[idx+1:])
		s = s[:idx]
	}

	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		// container port only
		pm.ContainerPort, _ = strconv.Atoi(parts[0])
	case 2:
		// host_port:container_port
		pm.HostPort, _ = strconv.Atoi(parts[0])
		pm.ContainerPort, _ = strconv.Atoi(parts[1])
	case 3:
		// host_ip:host_port:container_port
		pm.HostIP = parts[0]
		pm.HostPort, _ = strconv.Atoi(parts[1])
		pm.ContainerPort, _ = strconv.Atoi(parts[2])
	}

	return pm
}

// parsePortMap parses long-form port mapping {target, published, host_ip, protocol, mode}.
func parsePortMap(m map[string]any) model.PortMapping {
	pm := model.PortMapping{Protocol: "tcp"}

	if v, ok := m["target"]; ok {
		pm.ContainerPort = toInt(v)
	}
	if v, ok := m["published"]; ok {
		pm.HostPort = toInt(v)
	}
	if v, ok := m["host_ip"]; ok {
		pm.HostIP = toString(v)
	}
	if v, ok := m["protocol"]; ok {
		pm.Protocol = toString(v)
	}
	if pm.Protocol == "" {
		pm.Protocol = "tcp"
	}

	// Build a Raw representation.
	raw := ""
	if pm.HostIP != "" {
		raw = pm.HostIP + ":"
	}
	if pm.HostPort != 0 {
		raw += strconv.Itoa(pm.HostPort) + ":"
	}
	raw += strconv.Itoa(pm.ContainerPort)
	if pm.Protocol != "tcp" {
		raw += "/" + pm.Protocol
	}
	pm.Raw = raw

	return pm
}

// parseExpose converts expose entries (int or string) to []int.
func parseExpose(raw any) []int {
	if raw == nil {
		return nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []int
	for _, item := range items {
		out = append(out, toInt(item))
	}
	return out
}

// parseEnvMap handles environment as a map OR a list of "KEY=VAL" / "KEY" strings.
func parseEnvMap(raw any) map[string]string {
	if raw == nil {
		return nil
	}
	out := make(map[string]string)
	switch v := raw.(type) {
	case map[string]any:
		for k, val := range v {
			out[k] = toString(val)
		}
	case []any:
		for _, item := range v {
			s := toString(item)
			if idx := strings.IndexByte(s, '='); idx >= 0 {
				out[s[:idx]] = s[idx+1:]
			} else {
				out[s] = ""
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseStringOrList normalizes a string or []any into []string.
func parseStringOrList(raw any) []string {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			if s := toString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// parseStringList converts a []any to []string.
func parseStringList(raw any) []string {
	return parseStringOrList(raw)
}

// parseVolumes parses both short "src:dst[:ro]" and long-form volume entries.
func parseVolumes(raw any) []model.VolumeMount {
	if raw == nil {
		return nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []model.VolumeMount
	for _, item := range items {
		switch v := item.(type) {
		case string:
			out = append(out, parseVolumeString(v))
		case map[string]any:
			out = append(out, parseVolumeMap(v))
		}
	}
	return out
}

func parseVolumeString(s string) model.VolumeMount {
	vm := model.VolumeMount{Raw: s}
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		vm.Target = parts[0]
		vm.Type = volumeType("", parts[0])
	case 2:
		vm.Source = parts[0]
		vm.Target = parts[1]
		vm.Type = volumeType(parts[0], parts[1])
	case 3:
		vm.Source = parts[0]
		vm.Target = parts[1]
		vm.ReadOnly = strings.ToLower(parts[2]) == "ro"
		vm.Type = volumeType(parts[0], parts[1])
	}
	return vm
}

func parseVolumeMap(m map[string]any) model.VolumeMount {
	vm := model.VolumeMount{
		Type:     toString(m["type"]),
		Source:   toString(m["source"]),
		Target:   toString(m["target"]),
		ReadOnly: toBool(m["read_only"]),
	}
	if vm.Type == "" {
		vm.Type = volumeType(vm.Source, vm.Target)
	}
	// Build Raw.
	if vm.Source != "" {
		vm.Raw = vm.Source + ":" + vm.Target
		if vm.ReadOnly {
			vm.Raw += ":ro"
		}
	} else {
		vm.Raw = vm.Target
	}
	return vm
}

// volumeType infers "bind" or "volume" from the source path.
func volumeType(source, _ string) string {
	if source == "" {
		return "volume"
	}
	if strings.HasPrefix(source, "/") || strings.HasPrefix(source, ".") {
		return "bind"
	}
	return "volume"
}

// parseNetworkList handles networks as a list OR map (map -> keys).
func parseNetworkList(raw any) []string {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		var out []string
		for _, item := range v {
			if s := toString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(v))
		for k := range v {
			out = append(out, k)
		}
		return out
	}
	return nil
}

// parseDependsOn handles depends_on as list or map -> keys.
func parseDependsOn(raw any) []string {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		var out []string
		for _, item := range v {
			if s := toString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(v))
		for k := range v {
			out = append(out, k)
		}
		return out
	}
	return nil
}

// parseLabels handles labels as map OR list of "k=v" strings.
func parseLabels(raw any) map[string]string {
	if raw == nil {
		return nil
	}
	out := make(map[string]string)
	switch v := raw.(type) {
	case map[string]any:
		for k, val := range v {
			out[k] = toString(val)
		}
	case []any:
		for _, item := range v {
			s := toString(item)
			if idx := strings.IndexByte(s, '='); idx >= 0 {
				out[s[:idx]] = s[idx+1:]
			} else {
				out[s] = ""
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseDeployConfig extracts deploy.resources.limits.
func parseDeployConfig(raw any) *model.DeployConfig {
	if raw == nil {
		return nil
	}
	deployMap, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	resources, ok := deployMap["resources"].(map[string]any)
	if !ok {
		return nil
	}
	limits, ok := resources["limits"].(map[string]any)
	if !ok {
		return nil
	}
	dc := &model.DeployConfig{}
	if mem := toString(limits["memory"]); mem != "" {
		dc.MemoryLimit = mem
		dc.HasLimits = true
	}
	if cpu := toString(limits["cpus"]); cpu != "" {
		dc.CPULimit = cpu
		dc.HasLimits = true
	}
	if !dc.HasLimits {
		return nil
	}
	return dc
}

// parseTopNetworks converts top-level networks into model.Network map.
func parseTopNetworks(raw any) map[string]model.Network {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]model.Network, len(m))
	for k, v := range m {
		n := model.Network{}
		if vm, ok := v.(map[string]any); ok {
			n.Name = toString(vm["name"])
			n.Driver = toString(vm["driver"])
			n.External = toBool(vm["external"])
			n.Internal = toBool(vm["internal"])
		}
		out[k] = n
	}
	return out
}

// parseTopVolumes converts top-level volumes into model.Volume map.
func parseTopVolumes(raw any) map[string]model.Volume {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]model.Volume, len(m))
	for k, v := range m {
		vol := model.Volume{}
		if vm, ok := v.(map[string]any); ok {
			vol.Name = toString(vm["name"])
			vol.Driver = toString(vm["driver"])
			vol.External = toBool(vm["external"])
		}
		out[k] = vol
	}
	return out
}

// parseTopSecrets converts top-level secrets into model.Secret map.
func parseTopSecrets(raw any) map[string]model.Secret {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]model.Secret, len(m))
	for k, v := range m {
		sec := model.Secret{}
		if vm, ok := v.(map[string]any); ok {
			sec.Name = toString(vm["name"])
			sec.File = toString(vm["file"])
			sec.Environment = toString(vm["environment"])
			sec.External = toBool(vm["external"])
		}
		out[k] = sec
	}
	return out
}

// ---------------------------------------------------------------------------
// Env interpolation
// ---------------------------------------------------------------------------

var (
	reVarDefault = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*):-([^}]*)\}`)
	reVarBrace   = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	reVarSimple  = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
)

// interpolate replaces ${VAR:-default}, ${VAR}, and $VAR in a string.
func interpolate(s string, env map[string]string) string {
	// ${VAR:-default} first.
	s = reVarDefault.ReplaceAllStringFunc(s, func(match string) string {
		sub := reVarDefault.FindStringSubmatch(match)
		key, def := sub[1], sub[2]
		if val, ok := env[key]; ok && val != "" {
			return val
		}
		if val := os.Getenv(key); val != "" {
			return val
		}
		return def
	})
	// ${VAR}.
	s = reVarBrace.ReplaceAllStringFunc(s, func(match string) string {
		sub := reVarBrace.FindStringSubmatch(match)
		key := sub[1]
		if val, ok := env[key]; ok {
			return val
		}
		return os.Getenv(key)
	})
	// $VAR (simple, not inside braces).
	s = reVarSimple.ReplaceAllStringFunc(s, func(match string) string {
		key := match[1:]
		if val, ok := env[key]; ok {
			return val
		}
		return os.Getenv(key)
	})
	return s
}

// interpolateStack applies variable interpolation to all string fields in the
// stack that compose would interpolate.
func interpolateStack(s *model.Stack, env map[string]string) {
	for _, svc := range s.Services {
		svc.Image = interpolate(svc.Image, env)
		svc.Build = interpolate(svc.Build, env)
		svc.NetworkMode = interpolate(svc.NetworkMode, env)
		svc.User = interpolate(svc.User, env)
		svc.Restart = interpolate(svc.Restart, env)

		newEnv := make(map[string]string, len(svc.Environment))
		for k, v := range svc.Environment {
			newEnv[k] = interpolate(v, env)
		}
		svc.Environment = newEnv

		for i, v := range svc.Volumes {
			svc.Volumes[i].Source = interpolate(v.Source, env)
			svc.Volumes[i].Target = interpolate(v.Target, env)
		}

		newLabels := make(map[string]string, len(svc.Labels))
		for k, v := range svc.Labels {
			newLabels[k] = interpolate(v, env)
		}
		svc.Labels = newLabels
	}
}

// ---------------------------------------------------------------------------
// Git check for committed .env
// ---------------------------------------------------------------------------

func isEnvCommitted(envPath string) bool {
	dir := filepath.Dir(envPath)
	base := filepath.Base(envPath)
	cmd := exec.Command("git", "-C", dir, "ls-files", "--error-unmatch", base) // #nosec G204 -- git invoked via exec.Command with explicit args (no shell); path is operator-supplied; used to detect a committed .env
	return cmd.Run() == nil
}

// ---------------------------------------------------------------------------
// Firewall parsing
// ---------------------------------------------------------------------------

func isUFW(text string) bool {
	return strings.Contains(text, "Status:") ||
		strings.Contains(text, "Default:") ||
		strings.Contains(text, "ALLOW") ||
		strings.Contains(text, "DENY") ||
		strings.Contains(text, "ufw")
}

// parseUFW parses `ufw status` or `ufw status numbered` output.
func parseUFW(fw *model.FirewallConfig, text string) {
	fw.Engine = model.FirewallUFW

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)

		// Default incoming policy.
		if strings.HasPrefix(strings.ToLower(line), "default:") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "deny") {
				fw.DefaultIncoming = "deny"
			} else if strings.Contains(lower, "allow") {
				fw.DefaultIncoming = "allow"
			}
			continue
		}

		// Skip header lines.
		if line == "" || strings.HasPrefix(line, "Status:") ||
			strings.HasPrefix(line, "To ") || strings.HasPrefix(line, "--") ||
			strings.HasPrefix(line, "Logging:") || strings.HasPrefix(line, "Profiles:") {
			continue
		}

		// Strip optional numbered prefix like "[ 1] ".
		if strings.HasPrefix(line, "[") {
			if end := strings.Index(line, "]"); end >= 0 {
				line = strings.TrimSpace(line[end+1:])
			}
		}

		rule := parseUFWLine(line)
		if rule != nil {
			fw.Rules = append(fw.Rules, *rule)
		}
	}
}

// parseUFWLine parses a single UFW rule line.
// Examples:
//
//	"5432  DENY  Anywhere"
//	"80/tcp  ALLOW  Anywhere"
//	"8080 on eth0           ALLOW IN    Anywhere"
func parseUFWLine(line string) *model.FirewallRule {
	// Normalize multiple spaces.
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}

	portProto := fields[0]
	// Determine action (ALLOW / DENY).
	action := ""
	for _, f := range fields[1:] {
		lower := strings.ToLower(f)
		if lower == "allow" || lower == "allow in" || lower == "allow out" {
			action = "allow"
			break
		}
		if lower == "deny" || lower == "reject" || lower == "limit" {
			action = "deny"
			break
		}
	}
	if action == "" {
		return nil
	}

	// Parse port and optional protocol from portProto.
	proto := "tcp"
	portStr := portProto
	if idx := strings.IndexByte(portProto, '/'); idx >= 0 {
		proto = strings.ToLower(portProto[idx+1:])
		portStr = portProto[:idx]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}

	return &model.FirewallRule{
		Action:   action,
		Port:     port,
		Protocol: proto,
		Raw:      line,
	}
}

// parseIptables parses `iptables -S` or `iptables -L` output.
func parseIptables(fw *model.FirewallConfig, text string) {
	fw.Engine = model.FirewallIptables

	// Detect default incoming policy.
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)

		// -P INPUT ACCEPT / DROP/REJECT
		if strings.HasPrefix(line, "-P INPUT") || strings.HasPrefix(line, "Chain INPUT") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "drop") || strings.Contains(lower, "reject") {
				fw.DefaultIncoming = "deny"
			} else if strings.Contains(lower, "accept") {
				fw.DefaultIncoming = "allow"
			}
		}

		// DOCKER-USER chain detection.
		if strings.Contains(line, "DOCKER-USER") {
			fw.HasDockerUserChain = true
		}

		// Parse INPUT rules.
		rule := parseIptablesLine(line)
		if rule != nil {
			fw.Rules = append(fw.Rules, *rule)
		}
	}
}

// parseIptablesLine handles both `-S` format and `-L` format.
//
// -S: "-A INPUT -p tcp --dport 5432 -j DROP"
// -L: "DROP tcp -- anywhere anywhere tcp dpt:5432"
func parseIptablesLine(line string) *model.FirewallRule {
	line = strings.TrimSpace(line)

	// -S style.
	if strings.HasPrefix(line, "-A INPUT") {
		return parseIptablesSLine(line)
	}

	// -L style: look for dpt:port pattern.
	if strings.Contains(line, "dpt:") {
		return parseIptablesLLine(line)
	}

	return nil
}

func parseIptablesSLine(line string) *model.FirewallRule {
	// Extract action.
	action := ""
	lower := strings.ToLower(line)
	if strings.Contains(lower, "-j accept") {
		action = "allow"
	} else if strings.Contains(lower, "-j drop") || strings.Contains(lower, "-j reject") {
		action = "deny"
	}
	if action == "" {
		return nil
	}

	// Extract protocol.
	proto := "tcp"
	if strings.Contains(lower, "-p udp") {
		proto = "udp"
	}

	// Extract dport.
	port := extractDport(line)
	if port == 0 {
		return nil
	}

	return &model.FirewallRule{
		Action:   action,
		Port:     port,
		Protocol: proto,
		Raw:      line,
	}
}

func parseIptablesLLine(line string) *model.FirewallRule {
	fields := strings.Fields(line)
	if len(fields) < 1 {
		return nil
	}

	action := ""
	switch strings.ToLower(fields[0]) {
	case "accept":
		action = "allow"
	case "drop", "reject":
		action = "deny"
	}
	if action == "" {
		return nil
	}

	proto := "tcp"
	if len(fields) > 1 && strings.ToLower(fields[1]) == "udp" {
		proto = "udp"
	}

	port := extractDport(line)
	if port == 0 {
		return nil
	}

	return &model.FirewallRule{
		Action:   action,
		Port:     port,
		Protocol: proto,
		Raw:      line,
	}
}

var reDport = regexp.MustCompile(`(?:--dport|dpt:)\s*(\d+)`)

func extractDport(line string) int {
	m := reDport.FindStringSubmatch(line)
	if m == nil {
		return 0
	}
	port, _ := strconv.Atoi(m[1])
	return port
}

// ---------------------------------------------------------------------------
// Proxy parsing
// ---------------------------------------------------------------------------

// middlewareInfo classifies a Traefik middleware by its security properties.
type middlewareInfo struct {
	hasAuth    bool
	hasHeaders bool
}

// parseTraefikProxy reads Traefik labels from all services and builds routes.
func parseTraefikProxy(s *model.Stack, proxySvc *model.Service, pc *model.ProxyConfig) {
	_ = proxySvc // proxySvc itself doesn't carry routes; they're on app services

	// Collect all middleware names.
	// A middleware label looks like:
	//   traefik.http.middlewares.<name>.basicauth.users=...
	//   traefik.http.middlewares.<name>.forwardauth.address=...
	// We classify by name for quick lookup.
	middlewares := map[string]middlewareInfo{}

	for _, svc := range s.Services {
		for k := range svc.Labels {
			// traefik.http.middlewares.<name>.*
			if strings.HasPrefix(k, "traefik.http.middlewares.") {
				rest := k[len("traefik.http.middlewares."):]
				// next segment is the middleware name
				if dot := strings.IndexByte(rest, '.'); dot >= 0 {
					name := strings.ToLower(rest[:dot])
					info := middlewares[name]
					if isAuthMiddlewareName(name) {
						info.hasAuth = true
					}
					if isHeadersMiddlewareName(name) {
						info.hasHeaders = true
					}
					middlewares[name] = info
				}
			}
		}
	}

	// Detect dashboard exposure.
	for _, svc := range s.Services {
		if hasDashboardExposure(svc) {
			pc.DashboardExposed = true
		}
	}

	// Build per-service routes from traefik router labels.
	// Router labels: traefik.http.routers.<router>.*
	for _, svc := range s.Services {
		routes := parseTraefikRoutes(svc, middlewares)
		pc.Routes = append(pc.Routes, routes...)
	}
}

func hasDashboardExposure(svc *model.Service) bool {
	// Check command / args for --api.insecure=true.
	cmdStr := ""
	if raw, ok := svc.Raw["command"]; ok {
		switch v := raw.(type) {
		case string:
			cmdStr = v
		case []any:
			var parts []string
			for _, p := range v {
				parts = append(parts, toString(p))
			}
			cmdStr = strings.Join(parts, " ")
		}
	}
	if strings.Contains(cmdStr, "--api.insecure=true") {
		return true
	}

	// Check labels.
	for k, v := range svc.Labels {
		// traefik.http.routers.*.entrypoints containing "traefik" or "dashboard"
		if strings.Contains(k, ".entrypoints") {
			if strings.Contains(strings.ToLower(v), "traefik") {
				return true
			}
		}
		if k == "traefik.api.insecure" || k == "traefik.http.api.insecure" {
			if v == "true" {
				return true
			}
		}
	}

	// Check environment variables (some traefik images use env vars).
	for k, v := range svc.Environment {
		if strings.Contains(strings.ToLower(k), "api_insecure") || strings.Contains(strings.ToLower(k), "api.insecure") {
			if v == "true" {
				return true
			}
		}
	}
	return false
}

var reHostRule = regexp.MustCompile(`Host\(` + "`" + `([^` + "`" + `]+)` + "`" + `\)`)

func parseTraefikRoutes(svc *model.Service, middlewares map[string]middlewareInfo) []model.ProxyRoute {
	// Collect all router names from labels.
	routers := map[string]bool{}
	for k := range svc.Labels {
		if strings.HasPrefix(k, "traefik.http.routers.") {
			rest := k[len("traefik.http.routers."):]
			if dot := strings.IndexByte(rest, '.'); dot >= 0 {
				routers[rest[:dot]] = true
			}
		}
	}

	var routes []model.ProxyRoute
	for router := range routers {
		route := model.ProxyRoute{Service: svc.Name}
		prefix := "traefik.http.routers." + router + "."

		// Rule -> Host.
		if rule, ok := svc.Labels[prefix+"rule"]; ok {
			m := reHostRule.FindStringSubmatch(rule)
			if m != nil {
				route.Host = m[1]
				route.Wildcard = strings.Contains(m[1], "*")
			}
		}

		// TLS.
		if tls, ok := svc.Labels[prefix+"tls"]; ok && tls == "true" {
			route.TLS = true
		}
		// entrypoints containing "websecure" or "https" -> TLS.
		if ep, ok := svc.Labels[prefix+"entrypoints"]; ok {
			lower := strings.ToLower(ep)
			if strings.Contains(lower, "websecure") || strings.Contains(lower, "https") {
				route.TLS = true
			}
		}

		// Middlewares.
		if mw, ok := svc.Labels[prefix+"middlewares"]; ok {
			for _, name := range strings.Split(mw, ",") {
				name = strings.TrimSpace(strings.ToLower(name))
				if isAuthMiddlewareName(name) {
					route.HasAuth = true
				}
				if isHeadersMiddlewareName(name) {
					route.SecurityHeaders = true
				}
				if info, found := middlewares[name]; found {
					if info.hasAuth {
						route.HasAuth = true
					}
					if info.hasHeaders {
						route.SecurityHeaders = true
					}
				}
			}
		}

		routes = append(routes, route)
	}
	return routes
}

func isAuthMiddlewareName(name string) bool {
	for _, kw := range []string{"auth", "authelia", "authentik", "basicauth", "forward-auth", "forwardauth"} {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

func isHeadersMiddlewareName(name string) bool {
	for _, kw := range []string{"headers", "securityheaders", "security-headers"} {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

// enrichProxyFromFile does a best-effort text parse of a Caddy/nginx config file.
func enrichProxyFromFile(pc *model.ProxyConfig, path string) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI argument; local CLI reading the user's own file
	if err != nil {
		return
	}
	text := string(data)
	pc.Raw = text

	switch pc.Kind {
	case model.ProxyCaddy:
		enrichCaddyConfig(pc, text)
	case model.ProxyNginx, model.ProxyNPM:
		enrichNginxConfig(pc, text)
	}
}

func enrichCaddyConfig(pc *model.ProxyConfig, text string) {
	// Extract server_name / host patterns and reverse_proxy / listen :443.
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		// Caddyfile: "<host> {" block header.
		if strings.HasSuffix(line, "{") {
			host := strings.TrimSuffix(line, "{")
			host = strings.TrimSpace(host)
			if host != "" && !strings.ContainsAny(host, " \t") {
				route := model.ProxyRoute{Host: host, TLS: true} // Caddy auto-TLS
				pc.Routes = append(pc.Routes, route)
			}
		}
	}
}

func enrichNginxConfig(pc *model.ProxyConfig, text string) {
	var routes []model.ProxyRoute
	var current *model.ProxyRoute

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "server_name") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				host := strings.TrimSuffix(parts[1], ";")
				if current == nil {
					r := model.ProxyRoute{Host: host}
					routes = append(routes, r)
					current = &routes[len(routes)-1]
				} else {
					current.Host = host
				}
			}
		}

		if strings.Contains(line, "listen 443") && strings.Contains(line, "ssl") {
			if current != nil {
				current.TLS = true
			}
		}
	}

	pc.Routes = append(pc.Routes, routes...)
}

// ---------------------------------------------------------------------------
// Primitive helpers
// ---------------------------------------------------------------------------

func toString(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func toBool(v any) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		b, _ := strconv.ParseBool(val)
		return b
	case int:
		return val != 0
	}
	return false
}

func toInt(v any) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case string:
		n, _ := strconv.Atoi(val)
		return n
	}
	return 0
}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
