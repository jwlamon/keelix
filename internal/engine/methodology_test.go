package engine

import (
	"strings"
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestMethodologyMentionsCollection(t *testing.T) {
	// No signals: disabled disclosure.
	off := methodology(model.ScanOptions{NoProbe: true}, nil)
	if !strings.Contains(off, "inside-out collection was not performed") {
		t.Errorf("expected disabled-collection disclosure, got: %q", off)
	}

	// Signals with root=true: must say "privileged", must not say "unprivileged".
	privSig := &model.Signals{
		Privilege: model.Privilege{Root: true, EUID: 0},
		Sockets:   []model.ListeningSocket{{Proto: "tcp", Port: 80}},
	}
	priv := methodology(model.ScanOptions{NoProbe: true}, privSig)
	if !strings.Contains(priv, "inside-out collection ran") {
		t.Errorf("expected enabled-collection disclosure, got: %q", priv)
	}
	if !strings.Contains(priv, "privileged") {
		t.Errorf("expected privilege disclosure, got: %q", priv)
	}
	if strings.Contains(priv, "unprivileged") {
		t.Errorf("should not say 'unprivileged' when root=true, got: %q", priv)
	}

	// Signals with root=false: must say "unprivileged".
	unprivSig := &model.Signals{
		Privilege: model.Privilege{Root: false, EUID: 1000},
		Sockets:   []model.ListeningSocket{{Proto: "tcp", Port: 80}},
	}
	unpriv := methodology(model.ScanOptions{NoProbe: true}, unprivSig)
	if !strings.Contains(unpriv, "inside-out collection ran") {
		t.Errorf("expected enabled-collection disclosure (unprivileged), got: %q", unpriv)
	}
	if !strings.Contains(unpriv, "unprivileged") {
		t.Errorf("expected unprivileged disclosure, got: %q", unpriv)
	}

	// Signals present but only sockets populated: must mention sockets, must NOT
	// claim configs or packages were captured.
	sockOnlySig := &model.Signals{
		Sockets: []model.ListeningSocket{{Proto: "tcp", Port: 443}},
	}
	sockOnly := methodology(model.ScanOptions{NoProbe: true}, sockOnlySig)
	if !strings.Contains(sockOnly, "inside-out collection ran") {
		t.Errorf("expected collection disclosure for sockets-only signals, got: %q", sockOnly)
	}
	if strings.Contains(sockOnly, "config facts") {
		t.Errorf("must NOT claim config facts when Configs is empty, got: %q", sockOnly)
	}
	if strings.Contains(sockOnly, "package state") {
		t.Errorf("must NOT claim package facts when Packages is empty, got: %q", sockOnly)
	}

	// Empty Signals struct (no domains populated): treated as no collection.
	emptySig := &model.Signals{}
	emptyMethod := methodology(model.ScanOptions{NoProbe: true}, emptySig)
	if !strings.Contains(emptyMethod, "inside-out collection was not performed") {
		t.Errorf("empty Signals should be treated as no collection, got: %q", emptyMethod)
	}

	// Signals with configs populated: must mention configs.
	configSig := &model.Signals{
		Configs: []model.ConfigFact{{Source: "/etc/docker/daemon.json", SchemaKnown: true}},
	}
	configMethod := methodology(model.ScanOptions{NoProbe: true}, configSig)
	if !strings.Contains(configMethod, "config facts") {
		t.Errorf("must mention config facts when Configs is non-empty, got: %q", configMethod)
	}
}
