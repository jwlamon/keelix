// Package all blank-imports every check package so their init() functions run
// and populate the check registry (model.Register). Import this package for its
// side effects from any binary that needs the full check library:
//
//	import _ "github.com/jakelamon/keelix/internal/checks/all"
package all

import (
	_ "github.com/jakelamon/keelix/internal/checks/aiagent"
	_ "github.com/jakelamon/keelix/internal/checks/auth"
	_ "github.com/jakelamon/keelix/internal/checks/dns"
	_ "github.com/jakelamon/keelix/internal/checks/exposure"
	_ "github.com/jakelamon/keelix/internal/checks/firewall"
	_ "github.com/jakelamon/keelix/internal/checks/hardening"
	_ "github.com/jakelamon/keelix/internal/checks/host"
	_ "github.com/jakelamon/keelix/internal/checks/mcp"
	_ "github.com/jakelamon/keelix/internal/checks/proxy"
	_ "github.com/jakelamon/keelix/internal/checks/secrets"
	_ "github.com/jakelamon/keelix/internal/checks/service"
	_ "github.com/jakelamon/keelix/internal/checks/supplychain"
	_ "github.com/jakelamon/keelix/internal/checks/tlschk"
)
