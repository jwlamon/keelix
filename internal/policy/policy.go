// Package policy implements a local policy-as-code engine for Keelix.
// Policies are org-defined custom rules evaluated over the parsed Stack and
// emitted as POLICY-* findings. They are NOT part of the compliance catalog or
// the registered-check registry, so the catalog↔registry guard test is unaffected.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/jwlamon/keelix/internal/model"
)

// Policy is a JSON-loadable set of org-defined custom rules.
type Policy struct {
	// DenyImages is a list of image glob patterns (path.Match) that are disallowed.
	// Example: ["*:latest", "myrepo/*:dev"]
	DenyImages []string `json:"deny_images,omitempty"`
	// DenyHostPorts lists host ports that must not be published.
	DenyHostPorts []int `json:"deny_host_ports,omitempty"`
	// DenyPrivileged disallows containers running in privileged mode.
	DenyPrivileged bool `json:"deny_privileged,omitempty"`
	// RequireLabel requires every service to carry this label key.
	RequireLabel string `json:"require_label,omitempty"`
}

// Load reads and parses a JSON policy file from path.
func Load(filePath string) (Policy, error) {
	b, err := os.ReadFile(filePath) // #nosec G304 -- path is an operator-supplied CLI argument; local CLI reading the user's own file
	if err != nil {
		return Policy{}, fmt.Errorf("policy: read %q: %w", filePath, err)
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return Policy{}, fmt.Errorf("policy: parse %q: %w", filePath, err)
	}
	return p, nil
}

// Evaluate runs all policy rules against stack and returns any custom findings.
// Findings use POLICY-* check IDs and the group "Custom policy".
// They are appended to the engine findings AFTER the registered-check loop.
func (p Policy) Evaluate(stack *model.Stack) []model.Finding {
	var findings []model.Finding

	for _, svc := range stack.Services {
		// DenyImages — glob match
		for _, pattern := range p.DenyImages {
			matched, err := path.Match(pattern, svc.Image)
			if err != nil || !matched {
				continue
			}
			findings = append(findings, model.Finding{
				CheckID:  "POLICY-IMAGE",
				Group:    "Custom policy",
				Title:    fmt.Sprintf("Image %q matches denied pattern %q", svc.Image, pattern),
				Severity: model.SeverityWarning,
				Service:  svc.Name,
				Resource: svc.Image,
				Detail:   fmt.Sprintf("Your org policy disallows images matching %q. Service %q uses %q.", pattern, svc.Name, svc.Image),
				Fix: model.Fix{
					Summary: fmt.Sprintf("Change the image tag for service %q to a non-matching value.", svc.Name),
				},
			})
		}

		// DenyHostPorts
		for _, port := range p.DenyHostPorts {
			for _, pm := range svc.Ports {
				if pm.HostPort == port {
					findings = append(findings, model.Finding{
						CheckID:  "POLICY-PORT",
						Group:    "Custom policy",
						Title:    fmt.Sprintf("Service %q publishes denied host port %d", svc.Name, port),
						Severity: model.SeverityCritical,
						Service:  svc.Name,
						Resource: fmt.Sprintf("port %d", port),
						Detail:   fmt.Sprintf("Your org policy disallows publishing host port %d. Remove or remap the port mapping.", port),
						Fix: model.Fix{
							Summary: fmt.Sprintf("Remove the %d port mapping from service %q or change it to a non-denied port.", port, svc.Name),
						},
					})
				}
			}
		}

		// DenyPrivileged
		if p.DenyPrivileged && svc.Privileged {
			findings = append(findings, model.Finding{
				CheckID:  "POLICY-PRIVILEGED",
				Group:    "Custom policy",
				Title:    fmt.Sprintf("Service %q runs in privileged mode (org policy violation)", svc.Name),
				Severity: model.SeverityCritical,
				Service:  svc.Name,
				Detail:   fmt.Sprintf("Your org policy disallows privileged containers. Service %q has privileged: true.", svc.Name),
				Fix: model.Fix{
					Summary: fmt.Sprintf("Set `privileged: false` (or remove the key) for service %q.", svc.Name),
					Diff:    fmt.Sprintf("  %s:\n-   privileged: true\n+   # privileged removed", svc.Name),
				},
			})
		}

		// RequireLabel
		if p.RequireLabel != "" {
			if _, ok := svc.Labels[p.RequireLabel]; !ok {
				findings = append(findings, model.Finding{
					CheckID:  "POLICY-LABEL",
					Group:    "Custom policy",
					Title:    fmt.Sprintf("Service %q is missing required label %q", svc.Name, p.RequireLabel),
					Severity: model.SeverityWarning,
					Service:  svc.Name,
					Detail:   fmt.Sprintf("Your org policy requires every service to carry the label %q. Service %q does not have it.", p.RequireLabel, svc.Name),
					Fix: model.Fix{
						Summary: fmt.Sprintf("Add label %q to service %q.", p.RequireLabel, svc.Name),
						Diff:    fmt.Sprintf("  %s:\n    labels:\n+     %s: <value>", svc.Name, p.RequireLabel),
					},
				})
			}
		}
	}

	return findings
}
