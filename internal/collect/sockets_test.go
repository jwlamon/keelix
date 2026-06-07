package collect

import "testing"

// ssFixture is real `ss -tlnpH` output (header-less, -H): tcp listening
// sockets with process info. Columns: State Recv-Q Send-Q Local Peer Process.
const ssFixture = `LISTEN 0      4096       127.0.0.1:5432       0.0.0.0:*    users:(("postgres",pid=812,fd=7))
LISTEN 0      511          0.0.0.0:6379       0.0.0.0:*    users:(("redis-server",pid=901,fd=6))
LISTEN 0      4096            [::1]:5432          [::]:*    users:(("postgres",pid=812,fd=8))
LISTEN 0      128             [::]:22            [::]:*    users:(("sshd",pid=640,fd=4))
LISTEN 0      4096      100.64.1.20:8080       0.0.0.0:*    users:(("caddy",pid=1102,fd=9))
`

func TestParseSS(t *testing.T) {
	got := parseSS([]byte(ssFixture))
	if len(got) != 5 {
		t.Fatalf("parseSS returned %d sockets, want 5", len(got))
	}
	tests := []struct {
		idx   int
		bind  string
		port  int
		comm  string
		pid   int
		proto string
	}{
		{0, "127.0.0.1", 5432, "postgres", 812, "tcp"},
		{1, "0.0.0.0", 6379, "redis-server", 901, "tcp"},
		{2, "::1", 5432, "postgres", 812, "tcp"},
		{3, "::", 22, "sshd", 640, "tcp"},
		{4, "100.64.1.20", 8080, "caddy", 1102, "tcp"},
	}
	for _, tt := range tests {
		s := got[tt.idx]
		if s.Bind != tt.bind || s.Port != tt.port || s.Comm != tt.comm || s.PID != tt.pid || s.Proto != tt.proto {
			t.Errorf("socket[%d] = %+v, want bind=%s port=%d comm=%s pid=%d proto=%s",
				tt.idx, s, tt.bind, tt.port, tt.comm, tt.pid, tt.proto)
		}
	}
}

func TestParseSSIgnoresGarbage(t *testing.T) {
	got := parseSS([]byte("\n   \nnot a socket line\nLISTEN 0 0 1.2.3.4:bad 0.0.0.0:*\n"))
	if len(got) != 0 {
		t.Errorf("parseSS(garbage) = %d sockets, want 0", len(got))
	}
}

// lsofFixture is real `lsof -nP -iTCP -sTCP:LISTEN` output. Columns:
// COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME. We use the NAME column
// (host:port) and COMMAND/PID/USER.
const lsofFixture = `COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
postgres    812   lars    7u  IPv4 0x1a2b3c4d5e6f7080      0t0  TCP 127.0.0.1:5432 (LISTEN)
redis-ser   901   lars    6u  IPv4 0x1111222233334444      0t0  TCP *:6379 (LISTEN)
sshd        640   root    4u  IPv6 0x5555666677778888      0t0  TCP *:22 (LISTEN)
postgres    812   lars    8u  IPv6 0x9999aaaabbbbcccc      0t0  TCP [::1]:5432 (LISTEN)
`

func TestParseLsof(t *testing.T) {
	got := parseLsof([]byte(lsofFixture))
	if len(got) != 4 {
		t.Fatalf("parseLsof returned %d sockets, want 4", len(got))
	}
	tests := []struct {
		idx  int
		bind string
		port int
		comm string
		pid  int
	}{
		{0, "127.0.0.1", 5432, "postgres", 812},
		{1, "0.0.0.0", 6379, "redis-ser", 901},
		{2, "::", 22, "sshd", 640},
		{3, "::1", 5432, "postgres", 812},
	}
	for _, tt := range tests {
		s := got[tt.idx]
		if s.Bind != tt.bind || s.Port != tt.port || s.Comm != tt.comm || s.PID != tt.pid || s.Proto != "tcp" {
			t.Errorf("socket[%d] = %+v, want bind=%s port=%d comm=%s pid=%d",
				tt.idx, s, tt.bind, tt.port, tt.comm, tt.pid)
		}
	}
}
