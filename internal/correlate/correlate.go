// Package correlate infers which ports are intended to be public and produces
// a declared-vs-reachable-vs-intended diff for reports.
package correlate

import (
	"fmt"
	"sort"

	"github.com/jwlamon/keelix/internal/intel"
	"github.com/jwlamon/keelix/internal/model"
)

// PortFinding describes a single port in a correlation category.
type PortFinding struct {
	Port    int
	Service string // owning compose service if known, else ""
	Detail  string // e.g. "PostgreSQL"
}

// Report is the output of Correlate: a declared-vs-reachable-vs-intended diff.
type Report struct {
	Declared         []int         // host ports published to all interfaces in compose
	Reachable        []int         // ports observed open from outside (from probe)
	Intended         []int         // ports intended public
	Expected         []PortFinding // reachable AND intended (good)
	Surprises        []PortFinding // reachable AND NOT declared (unexpected exposure)
	SensitiveExposed []PortFinding // reachable AND a sensitive service AND NOT intended
	Blocked          []PortFinding // declared(public) AND NOT reachable
}

// String returns a short human summary for terminal/debug output.
func (r *Report) String() string {
	return fmt.Sprintf("declared=%v reachable=%v surprises=%v sensitive-exposed=%v",
		r.Declared, r.Reachable, portNums(r.Surprises), portNums(r.SensitiveExposed))
}

// portNums extracts port numbers from a slice of PortFinding.
func portNums(findings []PortFinding) []int {
	out := make([]int, len(findings))
	for i, f := range findings {
		out[i] = f.Port
	}
	return out
}

// owningService returns the name of the compose service that publishes the
// given host port to all interfaces, or "" if none is found.
func owningService(s *model.Stack, port int) string {
	if s == nil {
		return ""
	}
	for _, svc := range s.Services {
		for _, pm := range svc.Ports {
			if pm.HostPort == port && pm.PublishedToAllInterfaces() {
				return svc.Name
			}
		}
	}
	return ""
}

// BuildIntended constructs the set of ports intended to be public.
// It seeds from opts.IntendedPorts and then marks any service port published
// to all interfaces that intel.ExpectedPublicPort considers appropriate for
// the service's image. Never returns nil.
func BuildIntended(s *model.Stack, opts model.ScanOptions) map[int]bool {
	intended := make(map[int]bool)

	// Seed from operator-explicit ports.
	for _, p := range opts.IntendedPorts {
		intended[p] = true
	}

	// Walk each service's published ports.
	if s != nil {
		for _, svc := range s.Services {
			for _, pm := range svc.Ports {
				if pm.HostPort == 0 || !pm.PublishedToAllInterfaces() {
					continue
				}
				if intel.ExpectedPublicPort(svc.Image, pm.HostPort) {
					intended[pm.HostPort] = true
				}
			}
		}
	}

	return intended
}

// sortedInts returns a sorted copy of the keys of a map[int]bool (or any
// slice of ints after deduplication).
func sortedKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// Correlate produces a Report from a parsed stack and a probe result.
// p may be nil (offline / static analysis mode).
func Correlate(s *model.Stack, p *model.ProbeResult) *Report {
	r := &Report{}

	// --- Declared: sorted unique host ports published to all interfaces ---
	declaredSet := make(map[int]bool)
	if s != nil {
		for _, svc := range s.Services {
			for _, pm := range svc.Ports {
				if pm.HostPort == 0 || !pm.PublishedToAllInterfaces() {
					continue
				}
				declaredSet[pm.HostPort] = true
			}
		}
	}
	r.Declared = sortedKeys(declaredSet)

	// --- Reachable: sorted keys of p.Reachable where Open ---
	reachableSet := make(map[int]bool)
	if p != nil {
		for port, probe := range p.Reachable {
			if probe.Open {
				reachableSet[port] = true
			}
		}
	}
	r.Reachable = sortedKeys(reachableSet)

	// --- Intended: BuildIntended with empty opts ---
	intendedMap := BuildIntended(s, model.ScanOptions{})
	r.Intended = sortedKeys(intendedMap)

	// --- Expected: reachable AND intended ---
	for port := range reachableSet {
		if intendedMap[port] {
			svcName := owningService(s, port)
			detail := ""
			if info, ok := intel.LookupPort(port); ok {
				detail = info.Service
			}
			r.Expected = append(r.Expected, PortFinding{Port: port, Service: svcName, Detail: detail})
		}
	}
	sortFindings(r.Expected)

	// --- Surprises: reachable AND NOT in Declared (and not intended) ---
	for port := range reachableSet {
		if !declaredSet[port] && !intendedMap[port] {
			svcName := owningService(s, port)
			detail := ""
			if info, ok := intel.LookupPort(port); ok {
				detail = info.Service
			}
			r.Surprises = append(r.Surprises, PortFinding{Port: port, Service: svcName, Detail: detail})
		}
	}
	sortFindings(r.Surprises)

	// --- SensitiveExposed: reachable AND sensitive AND NOT intended ---
	for port := range reachableSet {
		if intel.IsSensitivePort(port) && !intendedMap[port] {
			svcName := owningService(s, port)
			detail := ""
			if info, ok := intel.LookupPort(port); ok {
				detail = info.Service
			}
			r.SensitiveExposed = append(r.SensitiveExposed, PortFinding{Port: port, Service: svcName, Detail: detail})
		}
	}
	sortFindings(r.SensitiveExposed)

	// --- Blocked: declared(public) AND NOT reachable (only meaningful when p != nil) ---
	if p != nil {
		for port := range declaredSet {
			if !reachableSet[port] {
				svcName := owningService(s, port)
				detail := ""
				if info, ok := intel.LookupPort(port); ok {
					detail = info.Service
				}
				r.Blocked = append(r.Blocked, PortFinding{Port: port, Service: svcName, Detail: detail})
			}
		}
		sortFindings(r.Blocked)
	}

	return r
}

// sortFindings sorts a []PortFinding by port number ascending.
func sortFindings(findings []PortFinding) {
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Port < findings[j].Port
	})
}
