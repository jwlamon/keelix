package model

import (
	"net"
	"strings"
)

func equalFold(a, b string) bool { return strings.EqualFold(a, b) }

// isLoopback reports whether host is a loopback address (127.0.0.0/8 or ::1).
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
