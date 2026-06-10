package engine

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func sig(values map[string]string) *model.Signals {
	return &model.Signals{
		Configs: []model.ConfigFact{
			{Source: "~/.config/test/mcp.json", SchemaKnown: true, Values: values},
		},
	}
}

func TestDeriveServerSpecs_Stdio(t *testing.T) {
	s := sig(map[string]string{
		"mcpServers.alpha.command":   "npx",
		"mcpServers.alpha.args.0":    "-y",
		"mcpServers.alpha.args.1":    "@scope/server",
		"mcpServers.alpha.env.TOKEN": "[secret]",
	})
	specs := deriveServerSpecs(s)
	if len(specs) != 1 {
		t.Fatalf("want 1 spec, got %d", len(specs))
	}
	sp := specs[0]
	if sp.Name != "alpha" || sp.Transport != "stdio" || sp.Command != "npx" {
		t.Fatalf("bad spec: %+v", sp)
	}
	if len(sp.Args) != 2 || sp.Args[0] != "-y" || sp.Args[1] != "@scope/server" {
		t.Fatalf("bad args (must be ordered): %+v", sp.Args)
	}
	if len(sp.EnvKeys) != 1 || sp.EnvKeys[0] != "TOKEN" {
		t.Fatalf("bad env keys: %+v", sp.EnvKeys)
	}
}

func TestDeriveServerSpecs_HTTP(t *testing.T) {
	s := sig(map[string]string{
		"mcpServers.remote.type": "http",
		"mcpServers.remote.url":  "https://mcp.example.com/rpc",
	})
	specs := deriveServerSpecs(s)
	if len(specs) != 1 {
		t.Fatalf("want 1 spec, got %d", len(specs))
	}
	if specs[0].Transport != "http" || specs[0].URL != "https://mcp.example.com/rpc" {
		t.Fatalf("bad http spec: %+v", specs[0])
	}
}

func TestDeriveServerSpecs_NilAndEmpty(t *testing.T) {
	if got := deriveServerSpecs(nil); got != nil {
		t.Fatalf("nil signals => nil specs, got %+v", got)
	}
	if got := deriveServerSpecs(&model.Signals{}); len(got) != 0 {
		t.Fatalf("no configs => no specs, got %+v", got)
	}
}
