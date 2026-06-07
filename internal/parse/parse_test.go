package parse

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// writeFile writes content to name inside dir and returns the full path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---------------------------------------------------------------------------
// ParseCompose — port syntax
// ---------------------------------------------------------------------------

func TestParseCompose_PortSyntax(t *testing.T) {
	type tc struct {
		name          string
		yaml          string
		wantHostIP    string
		wantHostPort  int
		wantContainer int
		wantProtocol  string
	}
	cases := []tc{
		{
			name:          "container_only",
			yaml:          `5432`,
			wantHostPort:  0,
			wantContainer: 5432,
			wantProtocol:  "tcp",
		},
		{
			name:          "host_colon_container",
			yaml:          `"5432:5432"`,
			wantHostPort:  5432,
			wantContainer: 5432,
			wantProtocol:  "tcp",
		},
		{
			name:          "ip_host_container",
			yaml:          `"127.0.0.1:5432:5432"`,
			wantHostIP:    "127.0.0.1",
			wantHostPort:  5432,
			wantContainer: 5432,
			wantProtocol:  "tcp",
		},
		{
			name:          "all_interfaces",
			yaml:          `"0.0.0.0:80:80"`,
			wantHostIP:    "0.0.0.0",
			wantHostPort:  80,
			wantContainer: 80,
			wantProtocol:  "tcp",
		},
		{
			name:          "udp_protocol",
			yaml:          `"8080:80/udp"`,
			wantHostPort:  8080,
			wantContainer: 80,
			wantProtocol:  "udp",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			compose := `
services:
  svc:
    image: test
    ports:
      - ` + c.yaml
			path := writeFile(t, dir, "docker-compose.yml", compose)
			s, err := ParseCompose(path)
			if err != nil {
				t.Fatal(err)
			}
			svc := s.Service("svc")
			if svc == nil {
				t.Fatal("service not found")
			}
			if len(svc.Ports) != 1 {
				t.Fatalf("want 1 port, got %d", len(svc.Ports))
			}
			p := svc.Ports[0]
			if p.HostIP != c.wantHostIP {
				t.Errorf("HostIP: want %q got %q", c.wantHostIP, p.HostIP)
			}
			if p.HostPort != c.wantHostPort {
				t.Errorf("HostPort: want %d got %d", c.wantHostPort, p.HostPort)
			}
			if p.ContainerPort != c.wantContainer {
				t.Errorf("ContainerPort: want %d got %d", c.wantContainer, p.ContainerPort)
			}
			if p.Protocol != c.wantProtocol {
				t.Errorf("Protocol: want %q got %q", c.wantProtocol, p.Protocol)
			}
		})
	}
}

func TestParseCompose_LongFormPort(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  db:
    image: postgres:16
    ports:
      - target: 5432
        published: 5433
        host_ip: "127.0.0.1"
        protocol: tcp
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("db")
	if svc == nil {
		t.Fatal("service not found")
	}
	if len(svc.Ports) != 1 {
		t.Fatalf("want 1 port, got %d", len(svc.Ports))
	}
	p := svc.Ports[0]
	if p.ContainerPort != 5432 {
		t.Errorf("ContainerPort: want 5432 got %d", p.ContainerPort)
	}
	if p.HostPort != 5433 {
		t.Errorf("HostPort: want 5433 got %d", p.HostPort)
	}
	if p.HostIP != "127.0.0.1" {
		t.Errorf("HostIP: want 127.0.0.1 got %q", p.HostIP)
	}
	if p.Protocol != "tcp" {
		t.Errorf("Protocol: want tcp got %q", p.Protocol)
	}
}

// ---------------------------------------------------------------------------
// ParseCompose — environment
// ---------------------------------------------------------------------------

func TestParseCompose_EnvMap(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  app:
    image: myapp
    environment:
      DB_HOST: postgres
      DB_PORT: 5432
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("app")
	if svc == nil {
		t.Fatal("service not found")
	}
	if svc.Environment["DB_HOST"] != "postgres" {
		t.Errorf("DB_HOST: got %q", svc.Environment["DB_HOST"])
	}
	if svc.Environment["DB_PORT"] != "5432" {
		t.Errorf("DB_PORT: got %q", svc.Environment["DB_PORT"])
	}
}

func TestParseCompose_EnvList(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  app:
    image: myapp
    environment:
      - "DB_HOST=postgres"
      - "DEBUG=true"
      - "KEY_ONLY"
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("app")
	if svc == nil {
		t.Fatal("service not found")
	}
	if svc.Environment["DB_HOST"] != "postgres" {
		t.Errorf("DB_HOST: got %q", svc.Environment["DB_HOST"])
	}
	if svc.Environment["DEBUG"] != "true" {
		t.Errorf("DEBUG: got %q", svc.Environment["DEBUG"])
	}
	if _, ok := svc.Environment["KEY_ONLY"]; !ok {
		t.Error("KEY_ONLY missing")
	}
}

// ---------------------------------------------------------------------------
// ParseCompose — volumes
// ---------------------------------------------------------------------------

func TestParseCompose_VolumeShortForm(t *testing.T) {
	cases := []struct {
		yaml     string
		wantType string
		wantSrc  string
		wantDst  string
		wantRO   bool
	}{
		{"./data:/app/data", "bind", "./data", "/app/data", false},
		{"/var/run/docker.sock:/var/run/docker.sock", "bind", "/var/run/docker.sock", "/var/run/docker.sock", false},
		{"pgdata:/var/lib/postgresql/data", "volume", "pgdata", "/var/lib/postgresql/data", false},
		{"./config:/etc/app:ro", "bind", "./config", "/etc/app", true},
		{"/data", "volume", "", "/data", false},
	}

	for _, c := range cases {
		t.Run(c.yaml, func(t *testing.T) {
			dir := t.TempDir()
			compose := `
services:
  svc:
    image: test
    volumes:
      - "` + c.yaml + `"
`
			path := writeFile(t, dir, "docker-compose.yml", compose)
			s, err := ParseCompose(path)
			if err != nil {
				t.Fatal(err)
			}
			svc := s.Service("svc")
			if svc == nil {
				t.Fatal("service not found")
			}
			if len(svc.Volumes) != 1 {
				t.Fatalf("want 1 volume, got %d", len(svc.Volumes))
			}
			v := svc.Volumes[0]
			if v.Type != c.wantType {
				t.Errorf("Type: want %q got %q", c.wantType, v.Type)
			}
			if v.Source != c.wantSrc {
				t.Errorf("Source: want %q got %q", c.wantSrc, v.Source)
			}
			if v.Target != c.wantDst {
				t.Errorf("Target: want %q got %q", c.wantDst, v.Target)
			}
			if v.ReadOnly != c.wantRO {
				t.Errorf("ReadOnly: want %v got %v", c.wantRO, v.ReadOnly)
			}
		})
	}
}

func TestParseCompose_VolumeLongForm(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  svc:
    image: test
    volumes:
      - type: bind
        source: ./config
        target: /etc/config
        read_only: true
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("svc")
	if svc == nil {
		t.Fatal("service not found")
	}
	if len(svc.Volumes) != 1 {
		t.Fatalf("want 1 volume, got %d", len(svc.Volumes))
	}
	v := svc.Volumes[0]
	if v.Type != "bind" {
		t.Errorf("Type: want bind got %q", v.Type)
	}
	if v.Source != "./config" {
		t.Errorf("Source: want ./config got %q", v.Source)
	}
	if v.Target != "/etc/config" {
		t.Errorf("Target: want /etc/config got %q", v.Target)
	}
	if !v.ReadOnly {
		t.Error("ReadOnly: want true got false")
	}
}

// ---------------------------------------------------------------------------
// ParseCompose — depends_on map form
// ---------------------------------------------------------------------------

func TestParseCompose_DependsOnMapForm(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  app:
    image: myapp
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
  db:
    image: postgres:16
  redis:
    image: redis:7
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("app")
	if svc == nil {
		t.Fatal("service not found")
	}
	if len(svc.DependsOn) != 2 {
		t.Fatalf("want 2 depends_on, got %d: %v", len(svc.DependsOn), svc.DependsOn)
	}
	sorted := append([]string(nil), svc.DependsOn...)
	sort.Strings(sorted)
	if sorted[0] != "db" || sorted[1] != "redis" {
		t.Errorf("DependsOn: got %v", sorted)
	}
}

// ---------------------------------------------------------------------------
// ParseCompose — deploy limits
// ---------------------------------------------------------------------------

func TestParseCompose_DeployLimits(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  app:
    image: myapp
    deploy:
      resources:
        limits:
          memory: 512m
          cpus: "0.5"
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("app")
	if svc == nil {
		t.Fatal("service not found")
	}
	if svc.Deploy == nil {
		t.Fatal("Deploy is nil")
	}
	if !svc.Deploy.HasLimits {
		t.Error("HasLimits: want true")
	}
	if svc.Deploy.MemoryLimit != "512m" {
		t.Errorf("MemoryLimit: got %q", svc.Deploy.MemoryLimit)
	}
	if svc.Deploy.CPULimit != "0.5" {
		t.Errorf("CPULimit: got %q", svc.Deploy.CPULimit)
	}
}

// ---------------------------------------------------------------------------
// LoadEnvFile
// ---------------------------------------------------------------------------

func TestLoadEnvFile(t *testing.T) {
	dir := t.TempDir()
	content := `
# comment
DB_HOST=postgres
DB_PASS="secret123"
SINGLE_QUOTED='hello world'
EXPORT_VAR=exported
export EXPORT2=also
BLANK=
NO_VALUE
`
	path := writeFile(t, dir, ".env", content)
	env, err := LoadEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}

	checks := map[string]string{
		"DB_HOST":       "postgres",
		"DB_PASS":       "secret123",
		"SINGLE_QUOTED": "hello world",
		"EXPORT_VAR":    "exported",
		"EXPORT2":       "also",
		"BLANK":         "",
	}
	for k, want := range checks {
		got, ok := env[k]
		if !ok {
			t.Errorf("key %q missing", k)
			continue
		}
		if got != want {
			t.Errorf("%s: want %q got %q", k, want, got)
		}
	}
	// NO_VALUE should be present with empty value.
	if _, ok := env["NO_VALUE"]; !ok {
		t.Error("NO_VALUE missing")
	}
}

// ---------------------------------------------------------------------------
// Env interpolation
// ---------------------------------------------------------------------------

func TestLoadStack_EnvInterpolation(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  app:
    image: myapp:${APP_VERSION}
    environment:
      DB_URL: "postgres://${DB_USER}:${DB_PASS}@db:5432/app"
      FALLBACK: "${MISSING_VAR:-defaultval}"
`
	writeFile(t, dir, "docker-compose.yml", compose)
	writeFile(t, dir, ".env", "APP_VERSION=1.2.3\nDB_USER=admin\nDB_PASS=hunter2\n")

	s, err := LoadStack(Options{
		ComposePath: filepath.Join(dir, "docker-compose.yml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("app")
	if svc == nil {
		t.Fatal("service not found")
	}
	if svc.Image != "myapp:1.2.3" {
		t.Errorf("Image: got %q", svc.Image)
	}
	if svc.Environment["DB_URL"] != "postgres://admin:hunter2@db:5432/app" {
		t.Errorf("DB_URL: got %q", svc.Environment["DB_URL"])
	}
	if svc.Environment["FALLBACK"] != "defaultval" {
		t.Errorf("FALLBACK: got %q", svc.Environment["FALLBACK"])
	}
}

// ---------------------------------------------------------------------------
// LoadFirewall — UFW
// ---------------------------------------------------------------------------

func TestLoadFirewall_UFW(t *testing.T) {
	dir := t.TempDir()
	content := `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

     To                         Action      From
     --                         ------      ----
22/tcp                         ALLOW IN    Anywhere
80                             ALLOW       Anywhere
443/tcp                        ALLOW       Anywhere
5432                           DENY        Anywhere
6379                           DENY        Anywhere
`
	path := writeFile(t, dir, "ufw.txt", content)
	fw, err := LoadFirewall(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(fw.Engine) != "ufw" {
		t.Errorf("Engine: want ufw got %q", fw.Engine)
	}
	if fw.DefaultIncoming != "deny" {
		t.Errorf("DefaultIncoming: want deny got %q", fw.DefaultIncoming)
	}

	// Look for deny rules.
	denied := map[int]bool{}
	allowed := map[int]bool{}
	for _, r := range fw.Rules {
		if r.Action == "deny" {
			denied[r.Port] = true
		}
		if r.Action == "allow" {
			allowed[r.Port] = true
		}
	}
	for _, p := range []int{5432, 6379} {
		if !denied[p] {
			t.Errorf("port %d should be denied", p)
		}
	}
	for _, p := range []int{22, 80, 443} {
		if !allowed[p] {
			t.Errorf("port %d should be allowed", p)
		}
	}
}

// ---------------------------------------------------------------------------
// LoadFirewall — iptables
// ---------------------------------------------------------------------------

func TestLoadFirewall_Iptables(t *testing.T) {
	dir := t.TempDir()
	content := `-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER-USER
-A DOCKER-USER -p tcp --dport 5432 -j DROP
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 5432 -j DROP
`
	path := writeFile(t, dir, "iptables.txt", content)
	fw, err := LoadFirewall(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(fw.Engine) != "iptables" {
		t.Errorf("Engine: want iptables got %q", fw.Engine)
	}
	if !fw.HasDockerUserChain {
		t.Error("HasDockerUserChain: want true")
	}
	if fw.DefaultIncoming != "deny" {
		t.Errorf("DefaultIncoming: want deny got %q", fw.DefaultIncoming)
	}

	denied := map[int]bool{}
	allowed := map[int]bool{}
	for _, r := range fw.Rules {
		if r.Action == "deny" {
			denied[r.Port] = true
		}
		if r.Action == "allow" {
			allowed[r.Port] = true
		}
	}
	if !denied[5432] {
		t.Error("port 5432 should be denied")
	}
	if !allowed[22] {
		t.Error("port 22 should be allowed")
	}
	if !allowed[80] {
		t.Error("port 80 should be allowed")
	}
}

// ---------------------------------------------------------------------------
// ParseProxyFromStack — Traefik api.insecure
// ---------------------------------------------------------------------------

func TestParseProxyFromStack_TraefikDashboard(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
    ports:
      - "80:80"
      - "8080:8080"
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	pc := ParseProxyFromStack(s)
	if pc == nil {
		t.Fatal("proxy config is nil")
	}
	if string(pc.Kind) != "traefik" {
		t.Errorf("Kind: want traefik got %q", pc.Kind)
	}
	if !pc.DashboardExposed {
		t.Error("DashboardExposed: want true")
	}
}

// ---------------------------------------------------------------------------
// ParseProxyFromStack — Traefik auth middleware route
// ---------------------------------------------------------------------------

func TestParseProxyFromStack_TraefikAuthRoute(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  traefik:
    image: traefik:v2.10
    ports:
      - "80:80"
      - "443:443"
  app:
    image: myapp
    labels:
      traefik.enable: "true"
      traefik.http.routers.app.rule: "Host(` + "`" + `app.example.com` + "`" + `)"
      traefik.http.routers.app.entrypoints: "websecure"
      traefik.http.routers.app.tls: "true"
      traefik.http.routers.app.middlewares: "authelia@docker,security-headers@docker"
  public:
    image: myapp2
    labels:
      traefik.enable: "true"
      traefik.http.routers.public.rule: "Host(` + "`" + `pub.example.com` + "`" + `)"
      traefik.http.routers.public.entrypoints: "web"
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	pc := ParseProxyFromStack(s)
	if pc == nil {
		t.Fatal("proxy config is nil")
	}

	// Find app route.
	var appRoute, pubRoute *struct {
		host    string
		tls     bool
		hasAuth bool
		hasSH   bool
	}
	for _, r := range pc.Routes {
		copy := r
		if copy.Host == "app.example.com" {
			appRoute = &struct {
				host    string
				tls     bool
				hasAuth bool
				hasSH   bool
			}{copy.Host, copy.TLS, copy.HasAuth, copy.SecurityHeaders}
		}
		if copy.Host == "pub.example.com" {
			pubRoute = &struct {
				host    string
				tls     bool
				hasAuth bool
				hasSH   bool
			}{copy.Host, copy.TLS, copy.HasAuth, copy.SecurityHeaders}
		}
	}
	if appRoute == nil {
		t.Fatal("app route not found")
	}
	if !appRoute.tls {
		t.Error("app route: TLS should be true")
	}
	if !appRoute.hasAuth {
		t.Error("app route: HasAuth should be true (authelia middleware)")
	}
	if !appRoute.hasSH {
		t.Error("app route: SecurityHeaders should be true (security-headers middleware)")
	}
	if pubRoute == nil {
		t.Fatal("public route not found")
	}
	if pubRoute.tls {
		t.Error("public route: TLS should be false")
	}
	if pubRoute.hasAuth {
		t.Error("public route: HasAuth should be false")
	}
}

// ---------------------------------------------------------------------------
// ParseProxyFromStack — nginx detection
// ---------------------------------------------------------------------------

func TestParseProxyFromStack_NginxDetection(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  nginx:
    image: nginx:latest
    ports:
      - "80:80"
      - "443:443"
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	pc := ParseProxyFromStack(s)
	if pc == nil {
		t.Fatal("proxy config is nil")
	}
	if string(pc.Kind) != "nginx" {
		t.Errorf("Kind: want nginx got %q", pc.Kind)
	}
}

// ---------------------------------------------------------------------------
// ParseCompose — misc fields
// ---------------------------------------------------------------------------

func TestParseCompose_MiscFields(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  app:
    image: myapp:1.0
    privileged: true
    network_mode: host
    user: "1000"
    read_only: true
    restart: always
    cap_add:
      - SYS_ADMIN
    cap_drop:
      - NET_RAW
    security_opt:
      - no-new-privileges:true
    networks:
      - frontend
      - backend
networks:
  frontend:
  backend:
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("app")
	if svc == nil {
		t.Fatal("service not found")
	}
	if !svc.Privileged {
		t.Error("Privileged: want true")
	}
	if svc.NetworkMode != "host" {
		t.Errorf("NetworkMode: got %q", svc.NetworkMode)
	}
	if svc.User != "1000" {
		t.Errorf("User: got %q", svc.User)
	}
	if !svc.ReadOnly {
		t.Error("ReadOnly: want true")
	}
	if svc.Restart != "always" {
		t.Errorf("Restart: got %q", svc.Restart)
	}
	if len(svc.CapAdd) != 1 || svc.CapAdd[0] != "SYS_ADMIN" {
		t.Errorf("CapAdd: got %v", svc.CapAdd)
	}
	if len(svc.CapDrop) != 1 || svc.CapDrop[0] != "NET_RAW" {
		t.Errorf("CapDrop: got %v", svc.CapDrop)
	}
	if len(svc.SecurityOpt) != 1 || svc.SecurityOpt[0] != "no-new-privileges:true" {
		t.Errorf("SecurityOpt: got %v", svc.SecurityOpt)
	}
	if len(s.Networks) != 2 {
		t.Errorf("top-level Networks: want 2 got %d", len(s.Networks))
	}
}

// ---------------------------------------------------------------------------
// ParseCompose — top-level volumes + secrets
// ---------------------------------------------------------------------------

func TestParseCompose_TopLevelVolumesSecrets(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  db:
    image: postgres:16
volumes:
  pgdata:
    driver: local
  external_vol:
    external: true
secrets:
  db_password:
    file: ./secrets/db_password.txt
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Volumes) != 2 {
		t.Errorf("Volumes: want 2 got %d", len(s.Volumes))
	}
	if !s.Volumes["external_vol"].External {
		t.Error("external_vol.External: want true")
	}
	if len(s.Secrets) != 1 {
		t.Errorf("Secrets: want 1 got %d", len(s.Secrets))
	}
	if s.Secrets["db_password"].File != "./secrets/db_password.txt" {
		t.Errorf("db_password.File: got %q", s.Secrets["db_password"].File)
	}
}

// ---------------------------------------------------------------------------
// ParseCompose — labels as list
// ---------------------------------------------------------------------------

func TestParseCompose_LabelsAsList(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  app:
    image: myapp
    labels:
      - "com.example.version=1.0"
      - "com.example.description=My App"
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("app")
	if svc == nil {
		t.Fatal("service not found")
	}
	if svc.Labels["com.example.version"] != "1.0" {
		t.Errorf("com.example.version: got %q", svc.Labels["com.example.version"])
	}
}

// ---------------------------------------------------------------------------
// LoadStack — project name
// ---------------------------------------------------------------------------

func TestLoadStack_ProjectName(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  app:
    image: myapp
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := LoadStack(Options{ComposePath: path})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Base(dir)
	if s.ProjectName != want {
		t.Errorf("ProjectName: want %q got %q", want, s.ProjectName)
	}
}

// ---------------------------------------------------------------------------
// LoadStack — auto-detect .env
// ---------------------------------------------------------------------------

func TestLoadStack_AutoDetectEnv(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  app:
    image: myapp:${VERSION}
`
	writeFile(t, dir, "docker-compose.yml", compose)
	writeFile(t, dir, ".env", "VERSION=9.9.9\n")

	s, err := LoadStack(Options{
		ComposePath: filepath.Join(dir, "docker-compose.yml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.EnvPath == "" {
		t.Error("EnvPath should be set")
	}
	svc := s.Service("app")
	if svc == nil {
		t.Fatal("service not found")
	}
	if svc.Image != "myapp:9.9.9" {
		t.Errorf("Image after interpolation: got %q", svc.Image)
	}
}

// ---------------------------------------------------------------------------
// interpolate — default values
// ---------------------------------------------------------------------------

func TestInterpolate_Default(t *testing.T) {
	env := map[string]string{"PRESENT": "yes"}
	cases := []struct {
		in   string
		want string
	}{
		{"${PRESENT:-fallback}", "yes"},
		{"${ABSENT:-fallback}", "fallback"},
		{"${PRESENT}", "yes"},
		{"plain", "plain"},
		{"${ABSENT}", ""},
	}
	for _, c := range cases {
		got := interpolate(c.in, env)
		if got != c.want {
			t.Errorf("interpolate(%q): want %q got %q", c.in, c.want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// ParsePortString edge cases
// ---------------------------------------------------------------------------

func TestParsePortString(t *testing.T) {
	cases := []struct {
		in            string
		wantHostIP    string
		wantHostPort  int
		wantContainer int
		wantProtocol  string
	}{
		{"5432", "", 0, 5432, "tcp"},
		{"5432:5432", "", 5432, 5432, "tcp"},
		{"127.0.0.1:5432:5432", "127.0.0.1", 5432, 5432, "tcp"},
		{"0.0.0.0:80:80", "0.0.0.0", 80, 80, "tcp"},
		{"8080:80/udp", "", 8080, 80, "udp"},
	}
	for _, c := range cases {
		pm := parsePortString(c.in)
		if pm.HostIP != c.wantHostIP {
			t.Errorf("%q HostIP: want %q got %q", c.in, c.wantHostIP, pm.HostIP)
		}
		if pm.HostPort != c.wantHostPort {
			t.Errorf("%q HostPort: want %d got %d", c.in, c.wantHostPort, pm.HostPort)
		}
		if pm.ContainerPort != c.wantContainer {
			t.Errorf("%q ContainerPort: want %d got %d", c.in, c.wantContainer, pm.ContainerPort)
		}
		if pm.Protocol != c.wantProtocol {
			t.Errorf("%q Protocol: want %q got %q", c.in, c.wantProtocol, pm.Protocol)
		}
	}
}

// ---------------------------------------------------------------------------
// Networks — map form on service
// ---------------------------------------------------------------------------

func TestParseCompose_ServiceNetworksMapForm(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  app:
    image: myapp
    networks:
      frontend:
        aliases:
          - myapp
      backend:
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("app")
	if svc == nil {
		t.Fatal("service not found")
	}
	if len(svc.Networks) != 2 {
		t.Errorf("Networks: want 2 got %d: %v", len(svc.Networks), svc.Networks)
	}
}

// ---------------------------------------------------------------------------
// UFW numbered output
// ---------------------------------------------------------------------------

func TestLoadFirewall_UFWNumbered(t *testing.T) {
	dir := t.TempDir()
	content := `Status: active
Default: deny (incoming), allow (outgoing)

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 5432                       DENY        Anywhere
[ 3] 80                         ALLOW IN    Anywhere
`
	path := writeFile(t, dir, "ufw.txt", content)
	fw, err := LoadFirewall(path)
	if err != nil {
		t.Fatal(err)
	}
	if fw.DefaultIncoming != "deny" {
		t.Errorf("DefaultIncoming: want deny got %q", fw.DefaultIncoming)
	}
	found5432 := false
	for _, r := range fw.Rules {
		if r.Port == 5432 && r.Action == "deny" {
			found5432 = true
		}
	}
	if !found5432 {
		t.Error("5432 DENY rule not found")
	}
}

// ---------------------------------------------------------------------------
// Traefik wildcard route
// ---------------------------------------------------------------------------

func TestParseProxyFromStack_TraefikWildcard(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  traefik:
    image: traefik:v2.10
  app:
    image: myapp
    labels:
      traefik.enable: "true"
      traefik.http.routers.catch.rule: "HostRegexp(` + "`" + `{catchall:.*}` + "`" + `)"
`
	// Use a simpler wildcard rule.
	compose = `
services:
  traefik:
    image: traefik:v2.10
  app:
    image: myapp
    labels:
      traefik.enable: "true"
      traefik.http.routers.catch.rule: "Host(` + "`" + `*.example.com` + "`" + `)"
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	pc := ParseProxyFromStack(s)
	if pc == nil {
		t.Fatal("proxy config is nil")
	}
	found := false
	for _, r := range pc.Routes {
		if r.Wildcard {
			found = true
		}
	}
	if !found {
		t.Error("wildcard route not detected")
	}
}

// ---------------------------------------------------------------------------
// MountsDockerSocket helper
// ---------------------------------------------------------------------------

func TestService_MountsDockerSocket(t *testing.T) {
	dir := t.TempDir()
	compose := `
services:
  portainer:
    image: portainer/portainer-ce
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - portainer_data:/data
volumes:
  portainer_data:
`
	path := writeFile(t, dir, "docker-compose.yml", compose)
	s, err := ParseCompose(path)
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Service("portainer")
	if svc == nil {
		t.Fatal("service not found")
	}
	if !svc.MountsDockerSocket() {
		t.Error("MountsDockerSocket: want true")
	}
}

// ---------------------------------------------------------------------------
// LoadFirewall returns nil engine gracefully for empty file
// ---------------------------------------------------------------------------

func TestLoadFirewall_Empty(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fw.txt", "")
	fw, err := LoadFirewall(path)
	if err != nil {
		t.Fatal(err)
	}
	if fw == nil {
		t.Fatal("expected non-nil FirewallConfig")
	}
}

// ---------------------------------------------------------------------------
// QF-3: LoadStack no-compose branch loads proxy config from ProxyConfigPath
// ---------------------------------------------------------------------------

func TestLoadStack_NoCompose_ProxyFromNginxConf(t *testing.T) {
	dir := t.TempDir()
	nginx := `
server {
    listen 443 ssl;
    server_name example.com;
}
`
	proxyPath := writeFile(t, dir, "nginx.conf", nginx)
	s, err := LoadStack(Options{ProxyConfigPath: proxyPath})
	if err != nil {
		t.Fatalf("LoadStack error: %v", err)
	}
	if s.Proxy == nil {
		t.Fatal("expected non-nil Proxy on no-compose scan with ProxyConfigPath set")
	}
	if s.Proxy.Kind != "nginx" {
		t.Errorf("expected kind=nginx, got %q", s.Proxy.Kind)
	}
	found := false
	for _, r := range s.Proxy.Routes {
		if r.Host == "example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected route for example.com from nginx.conf, got routes: %+v", s.Proxy.Routes)
	}
}

func TestLoadStack_NoCompose_ProxyKindCaddy(t *testing.T) {
	dir := t.TempDir()
	caddy := "example.com {\n  reverse_proxy localhost:3000\n}\n"
	proxyPath := writeFile(t, dir, "Caddyfile", caddy)
	s, err := LoadStack(Options{ProxyConfigPath: proxyPath})
	if err != nil {
		t.Fatalf("LoadStack error: %v", err)
	}
	if s.Proxy == nil {
		t.Fatal("expected non-nil Proxy for Caddyfile")
	}
	if s.Proxy.Kind != "caddy" {
		t.Errorf("expected kind=caddy, got %q", s.Proxy.Kind)
	}
}

func TestLoadStack_NoCompose_ProxyKindTraefik(t *testing.T) {
	dir := t.TempDir()
	traefik := "# traefik static config\nentryPoints:\n  web:\n    address: ':80'\n"
	proxyPath := writeFile(t, dir, "traefik.yml", traefik)
	s, err := LoadStack(Options{ProxyConfigPath: proxyPath})
	if err != nil {
		t.Fatalf("LoadStack error: %v", err)
	}
	if s.Proxy == nil {
		t.Fatal("expected non-nil Proxy for traefik.yml")
	}
	if s.Proxy.Kind != "traefik" {
		t.Errorf("expected kind=traefik, got %q", s.Proxy.Kind)
	}
}

func TestLoadStack_NoCompose_NoProxyPath_ProxyNil(t *testing.T) {
	// Without a ProxyConfigPath, the no-compose path must leave s.Proxy nil.
	s, err := LoadStack(Options{})
	if err != nil {
		t.Fatalf("LoadStack error: %v", err)
	}
	if s.Proxy != nil {
		t.Errorf("expected nil Proxy when no ProxyConfigPath, got %+v", s.Proxy)
	}
}
