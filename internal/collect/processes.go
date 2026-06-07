package collect

import (
	"strconv"
	"strings"

	"github.com/jwlamon/keelix/internal/model"
)

// populateProcessGroupsFromFiles enriches each ProcessFact in procs with the
// group names the process's UID belongs to, derived from raw /etc/passwd and
// /etc/group bytes.  It is a pure function with no subprocess calls.
//
// Algorithm:
//  1. Parse passwdBytes to build uid → username (primary account name).
//  2. Parse groupBytes to build username → []groupName (all groups that list
//     the username in their member field, plus the primary group by GID).
//  3. For each process, look up its UID in the uid→username map and then the
//     username in the groups map; set pf.Groups to the result.
//
// Both files are read by the caller (processes_linux.go) who annotates the
// os.ReadFile calls with // #nosec G304.  This function itself does no I/O.
func populateProcessGroupsFromFiles(procs []model.ProcessFact, passwdBytes, groupBytes []byte) {
	// Step 1: /etc/passwd → uid → (username, primaryGID)
	type passwdEntry struct {
		name       string
		primaryGID int
	}
	uidToEntry := make(map[int]passwdEntry)
	for _, raw := range strings.Split(string(passwdBytes), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// name:password:uid:gid:comment:home:shell
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}
		uidToEntry[uid] = passwdEntry{name: fields[0], primaryGID: gid}
	}

	// Step 2: /etc/group → gid → groupName, and username → []groupName
	// Two passes:
	//   pass A: build gid → groupName (for primary-group resolution)
	//   pass B: build username → []groupName from the member lists
	gidToName := make(map[int]string)
	// username → set of group names (use map to deduplicate)
	userGroups := make(map[string]map[string]struct{})

	for _, raw := range strings.Split(string(groupBytes), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// groupname:password:gid:member1,member2,...
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		groupName := fields[0]
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		gidToName[gid] = groupName

		// members field (index 3) may be absent or empty
		if len(fields) >= 4 && fields[3] != "" {
			for _, member := range strings.Split(fields[3], ",") {
				member = strings.TrimSpace(member)
				if member == "" {
					continue
				}
				if userGroups[member] == nil {
					userGroups[member] = make(map[string]struct{})
				}
				userGroups[member][groupName] = struct{}{}
			}
		}
	}

	// Step 3: for each process, resolve groups and set pf.Groups.
	for i := range procs {
		entry, ok := uidToEntry[procs[i].UID]
		if !ok {
			continue
		}
		grpSet := make(map[string]struct{})

		// Add primary group (by GID from passwd).
		if name, ok := gidToName[entry.primaryGID]; ok {
			grpSet[name] = struct{}{}
		}

		// Add supplemental groups (from /etc/group member lists).
		for g := range userGroups[entry.name] {
			grpSet[g] = struct{}{}
		}

		if len(grpSet) == 0 {
			continue
		}
		groups := make([]string, 0, len(grpSet))
		for g := range grpSet {
			groups = append(groups, g)
		}
		procs[i].Groups = groups
	}
}

// parseProcesses turns the output of a `ps -eo pid,uid,comm,args`-style dump
// into []model.ProcessFact. It is a pure function: the first line is treated as
// a header and skipped. Any KEY=VALUE token in the args is classified via
// classifyEnv (values are never stored). Each argv token is sanitized: tokens
// that classify as secrets are replaced with "[secret]". Returns nil for empty
// input.
func parseProcesses(b []byte) []model.ProcessFact {
	text := strings.TrimRight(string(b), "\n")
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	if len(lines) <= 1 {
		return []model.ProcessFact{}
	}
	out := make([]model.ProcessFact, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		uid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		comm := fields[2]
		rawArgs := fields[3:]
		pf := model.ProcessFact{
			Comm: comm,
			PID:  pid,
			UID:  uid,
			Args: sanitizeArgs(rawArgs),
		}
		for _, a := range rawArgs {
			if k, v, ok := splitEnvToken(a); ok {
				pf.Env = append(pf.Env, classifyEnv(k, v))
			}
		}
		out = append(out, pf)
	}
	return out
}

// sanitizeArgs returns a copy of args where each token that classifies as a
// secret is replaced with "[secret]". A token is classified as a secret when:
//   - It is a KEY=VALUE form whose key or value classifies as a secret, OR
//   - It is a bare value (no '=') with high entropy / secret-name shape, OR
//   - It contains a secret-name flag prefix like "--token=<value>".
func sanitizeArgs(args []string) []string {
	out := make([]string, len(args))
	for i, tok := range args {
		out[i] = sanitizeArgToken(tok)
	}
	return out
}

// sanitizeArgToken sanitizes a single argv token.
func sanitizeArgToken(tok string) string {
	// Handle KEY=VALUE and --flag=VALUE forms.
	if eq := strings.IndexByte(tok, '='); eq > 0 {
		key := tok[:eq]
		val := tok[eq+1:]
		// Strip leading dashes from flag names for key classification.
		bareKey := strings.TrimLeft(key, "-")
		if classOf(bareKey, val) == "secret" {
			return "[secret]"
		}
		return tok
	}
	// Bare token: classify treating the token as both name and value.
	// This catches high-entropy standalone tokens.
	if classOf(tok, tok) == "secret" {
		return "[secret]"
	}
	return tok
}

// splitEnvToken splits a "KEY=VALUE" token. It only treats a token as env-shaped
// when the key is a bare identifier (no slash), to avoid misreading flags.
func splitEnvToken(tok string) (key, value string, ok bool) {
	i := strings.IndexByte(tok, '=')
	if i <= 0 {
		return "", "", false
	}
	key = tok[:i]
	if strings.ContainsAny(key, "/.-") || strings.HasPrefix(key, "-") {
		return "", "", false
	}
	return key, tok[i+1:], true
}
