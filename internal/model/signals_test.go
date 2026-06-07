package model

import "testing"

func TestSocketByPort(t *testing.T) {
	s := &Signals{
		Sockets: []ListeningSocket{
			{Proto: "tcp", Bind: "127.0.0.1", Port: 5432, PID: 11, Comm: "postgres"},
			{Proto: "tcp", Bind: "0.0.0.0", Port: 6379, PID: 12, Comm: "redis-server"},
			{Proto: "tcp", Bind: "::", Port: 5432, PID: 13, Comm: "pgbouncer"},
		},
	}
	tests := []struct {
		name     string
		port     int
		wantOK   bool
		wantComm string
	}{
		{"first-match-wins", 5432, true, "postgres"},
		{"single-match", 6379, true, "redis-server"},
		{"no-match", 8080, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := s.SocketByPort(tt.port)
			if ok != tt.wantOK {
				t.Fatalf("SocketByPort(%d) ok = %v, want %v", tt.port, ok, tt.wantOK)
			}
			if ok && got.Comm != tt.wantComm {
				t.Errorf("SocketByPort(%d) comm = %q, want %q", tt.port, got.Comm, tt.wantComm)
			}
		})
	}
}

func TestSignalsVersion(t *testing.T) {
	if SignalsVersion != "1.0.0" {
		t.Errorf("SignalsVersion = %q, want %q", SignalsVersion, "1.0.0")
	}
}
