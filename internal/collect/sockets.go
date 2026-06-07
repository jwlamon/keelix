package collect

import (
	"strconv"
	"strings"

	"github.com/jwlamon/keelix/internal/model"
)

// parseSS parses header-less `ss -tlnpH` output into listening sockets. Each
// line looks like:
//
//	LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=812,fd=7))
//
// Malformed lines are skipped. Pure: no I/O.
func parseSS(b []byte) []model.ListeningSocket {
	var out []model.ListeningSocket
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if !strings.EqualFold(fields[0], "LISTEN") {
			continue
		}
		bind, port, ok := splitHostPort(fields[3])
		if !ok {
			continue
		}
		sock := model.ListeningSocket{Proto: "tcp", Bind: bind, Port: port}
		// Process column is the last field when present.
		if comm, pid, ok := parseSSProcess(fields[len(fields)-1]); ok {
			sock.Comm = comm
			sock.PID = pid
		}
		out = append(out, sock)
	}
	return out
}

// parseSSProcess extracts comm + pid from `users:(("postgres",pid=812,fd=7))`.
func parseSSProcess(s string) (comm string, pid int, ok bool) {
	i := strings.Index(s, `("`)
	if i < 0 {
		return "", 0, false
	}
	rest := s[i+2:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return "", 0, false
	}
	comm = rest[:j]
	k := strings.Index(rest, "pid=")
	if k < 0 {
		return comm, 0, true
	}
	num := rest[k+4:]
	end := strings.IndexAny(num, ",)")
	if end >= 0 {
		num = num[:end]
	}
	pid, err := strconv.Atoi(num)
	if err != nil {
		return comm, 0, true
	}
	return comm, pid, true
}

// parseLsof parses `lsof -nP -iTCP -sTCP:LISTEN` output into listening sockets.
// The NAME column (host:port) is the second-to-last field; "(LISTEN)" is last.
// The wildcard address "*" is normalized to "0.0.0.0" for IPv4 and "::" for
// IPv6 (determined by the TYPE column). Pure: no I/O.
func parseLsof(b []byte) []model.ListeningSocket {
	var out []model.ListeningSocket
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		if fields[0] == "COMMAND" {
			continue
		}
		if !strings.Contains(line, "(LISTEN)") {
			continue
		}
		// NAME is the field immediately before "(LISTEN)".
		name := fields[len(fields)-2]
		// TYPE column (index 4) determines whether wildcard "*" means IPv4 or IPv6.
		ipv6 := fields[4] == "IPv6"
		bind, port, ok := splitHostPortLsof(name, ipv6)
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		out = append(out, model.ListeningSocket{
			Proto: "tcp",
			Bind:  bind,
			Port:  port,
			Comm:  fields[0],
			PID:   pid,
		})
	}
	return out
}

// splitHostPortLsof is like splitHostPort but uses the ipv6 flag to normalize
// the wildcard address "*" to "::" (IPv6) or "0.0.0.0" (IPv4).
func splitHostPortLsof(tok string, ipv6 bool) (bind string, port int, ok bool) {
	idx := strings.LastIndex(tok, ":")
	if idx < 0 {
		return "", 0, false
	}
	host := tok[:idx]
	portStr := tok[idx+1:]

	// Strip IPv6 brackets.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "*" || host == "" {
		if ipv6 {
			host = "::"
		} else {
			host = "0.0.0.0"
		}
	}

	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, false
	}
	return host, p, true
}

// splitHostPort splits an "addr:port" token from ss/lsof into a normalized
// bind address and integer port. It handles bracketed IPv6 (`[::1]:5432`),
// bare IPv6 wildcard (`[::]:*`-style already bracketed), and the lsof wildcard
// host "*". A "*" port (ss peer column style) yields ok=false.
func splitHostPort(tok string) (bind string, port int, ok bool) {
	idx := strings.LastIndex(tok, ":")
	if idx < 0 {
		return "", 0, false
	}
	host := tok[:idx]
	portStr := tok[idx+1:]

	// Strip IPv6 brackets.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	switch host {
	case "*", "":
		host = "0.0.0.0"
	}

	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, false
	}
	return host, p, true
}
