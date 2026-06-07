package aiagent

import (
	"fmt"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&agt006{}) }

type agt006 struct{}

func (c *agt006) ID() string              { return catalog.Get("AGT006").ID }
func (c *agt006) Title() string           { return catalog.Get("AGT006").Title }
func (c *agt006) Group() model.CheckGroup { return catalog.Get("AGT006").Group }

func isLoopback(bind string) bool {
	return bind == "127.0.0.1" || bind == "::1"
}

func (c *agt006) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{NotAssessed("AGT006")}
	}

	var findings []model.Finding
	for _, sock := range ctx.Collector.Sockets {
		if !isAgentProcess(sock.Comm) {
			continue
		}
		if isLoopback(sock.Bind) {
			continue
		}
		f := catalog.Get("AGT006").Finding()
		f.ExposureClass = exposureFromBind(sock.Bind)
		f.Confidence = model.ConfidenceHigh
		f.Resource = fmt.Sprintf("socket %s:%d (pid %d)", sock.Bind, sock.Port, sock.PID)
		f.Evidence = fmt.Sprintf("agent process %q listening on non-loopback %s port %d", sock.Comm, sock.Bind, sock.Port)
		f.Fix = model.Fix{
			Summary: "Bind agent gateway to 127.0.0.1 only; use a reverse proxy with authentication if remote access is required.",
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("AGT006").Pass("No agent control surface listening on a non-loopback address.")}
	}
	return findings
}
