// Package host implements GroupHost checks (HST001–HST041).
// All checks are pure functions of *model.ScanContext: no I/O, no globals.
package host

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

// notAssessed returns a Finding for id with StatusNotAssessed.
func notAssessed(id string) model.Finding {
	f := catalog.Get(id).Finding()
	f.Status = model.StatusNotAssessed
	f.Detail = "inside-out collector data unavailable for this check; run with --collect"
	return f
}

// configBySchema returns the first ConfigFact in sigs.Configs whose SchemaID
// matches id and SchemaKnown is true.
func configBySchema(sigs *model.Signals, id string) (model.ConfigFact, bool) {
	if sigs == nil {
		return model.ConfigFact{}, false
	}
	for _, c := range sigs.Configs {
		if c.SchemaID == id && c.SchemaKnown {
			return c, true
		}
	}
	return model.ConfigFact{}, false
}

// fileByPath returns the FileFact for path if present in sigs.Files.
func fileByPath(sigs *model.Signals, path string) (model.FileFact, bool) {
	if sigs == nil {
		return model.FileFact{}, false
	}
	for _, ff := range sigs.Files {
		if ff.Path == path {
			return ff, true
		}
	}
	return model.FileFact{}, false
}

// exposureFromBind maps a socket bind address to an ExposureClass.
func exposureFromBind(bind string) model.ExposureClass {
	switch bind {
	case "127.0.0.1", "::1":
		return model.ExposureLocalhost
	case "0.0.0.0", "::":
		return model.ExposureInternet
	default:
		return model.ExposureLAN
	}
}

// sshdVal looks up key in a sshd-effective or sshd-static ConfigFact Values
// map, returning the value and whether the key was present.
func sshdVal(cf model.ConfigFact, key string) (string, bool) {
	v, ok := cf.Values[key]
	return v, ok
}

// hasProcess returns true if any ProcessFact in sigs has comm matching name.
func hasProcess(sigs *model.Signals, name string) bool {
	if sigs == nil {
		return false
	}
	for _, p := range sigs.Processes {
		if p.Comm == name {
			return true
		}
	}
	return false
}

// socketNonLoopback returns (socket, true) for the first listening socket on
// port whose bind is not loopback.
func socketNonLoopback(sigs *model.Signals, port int) (model.ListeningSocket, bool) {
	if sigs == nil {
		return model.ListeningSocket{}, false
	}
	for _, s := range sigs.Sockets {
		if s.Port == port && s.Bind != "127.0.0.1" && s.Bind != "::1" {
			return s, true
		}
	}
	return model.ListeningSocket{}, false
}
