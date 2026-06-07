// Package auth implements authentication/access checks (AUTH*).
package auth

import (
	"fmt"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/intel"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&auth001{}) }

type auth001 struct{}

func (c *auth001) ID() string              { return catalog.Get("AUTH001").ID }
func (c *auth001) Title() string           { return catalog.Get("AUTH001").Title }
func (c *auth001) Group() model.CheckGroup { return catalog.Get("AUTH001").Group }

// webPorts are ports that indicate a web-facing service.
var webPorts = map[int]bool{
	80: true, 443: true, 8080: true, 8081: true, 3000: true, 8096: true,
	8920: true, 3001: true, 8443: true, 8008: true, 8888: true,
}

// isAuthOrProxyImage returns true if the image base looks like an auth/proxy/identity service.
func isAuthOrProxyImage(image string) bool {
	base := strings.ToLower(intel.ImageBase(image))
	for _, kw := range []string{
		"authelia", "authentik", "traefik", "caddy", "nginx", "haproxy",
		"oauth2-proxy", "keycloak", "ldap", "pomerium",
	} {
		if strings.Contains(base, kw) {
			return true
		}
	}
	return false
}

// stackHasAuthService returns true if any service in the stack is an identity/auth middleware.
func stackHasAuthService(stack *model.Stack) bool {
	for _, svc := range stack.Services {
		base := strings.ToLower(intel.ImageBase(svc.Image))
		if strings.Contains(base, "authelia") || strings.Contains(base, "authentik") {
			return true
		}
	}
	return false
}

// proxyHasAuth returns true if the proxy config has a route for svcName with HasAuth==true.
func proxyHasAuth(proxy *model.ProxyConfig, svcName string) bool {
	if proxy == nil {
		return false
	}
	for _, r := range proxy.Routes {
		if r.Service == svcName && r.HasAuth {
			return true
		}
	}
	return false
}

// isPubliclyExposed returns true if the service publishes a web port on all interfaces.
func isPubliclyExposed(svc *model.Service) bool {
	for _, pm := range svc.Ports {
		if !pm.PublishedToAllInterfaces() {
			continue
		}
		if webPorts[pm.HostPort] || webPorts[pm.ContainerPort] {
			return true
		}
	}
	return false
}

func (c *auth001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessed("AUTH001")}
	}

	authSvcPresent := stackHasAuthService(ctx.Stack)

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		if !isPubliclyExposed(svc) {
			continue
		}
		// Skip auth/proxy images — they are the protection layer.
		if isAuthOrProxyImage(svc.Image) {
			continue
		}
		// Auth is present if the stack has an auth service globally, or
		// the proxy has an auth route for this service.
		if authSvcPresent {
			continue
		}
		if proxyHasAuth(ctx.Stack.Proxy, svc.Name) {
			continue
		}

		f := catalog.Get("AUTH001").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("service %s", svc.Name)
		f.Evidence = fmt.Sprintf("service %q publishes a web port to all interfaces with no authentication layer detected", svc.Name)
		f.Fix = model.Fix{
			Summary: "Place an identity-aware proxy (Authelia, Authentik, oauth2-proxy) in front of this service, or enable the service's built-in authentication.",
			DocURL:  "https://www.authelia.com/",
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("AUTH001").Pass("All publicly exposed services have an authentication layer.")}
	}
	return findings
}
