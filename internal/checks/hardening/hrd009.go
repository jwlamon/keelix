package hardening

import (
	"strconv"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hrd009{}) }

type hrd009 struct{}

func (c *hrd009) ID() string              { return catalog.Get("HRD009").ID }
func (c *hrd009) Title() string           { return catalog.Get("HRD009").Title }
func (c *hrd009) Group() model.CheckGroup { return catalog.Get("HRD009").Group }

const dockerSockPath = "/var/run/docker.sock"

func (c *hrd009) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HRD009")}
	}
	if ctx.Collector.Platform.OS == "darwin" {
		return []model.Finding{notAssessed("HRD009")}
	}
	ff, ok := fileByPath(ctx.Collector, dockerSockPath)
	if !ok || !ff.Exists {
		return []model.Finding{notAssessed("HRD009")}
	}
	if ff.Mode == "" {
		return []model.Finding{notAssessed("HRD009")}
	}
	mode, err := strconv.ParseUint(ff.Mode, 8, 32)
	if err != nil {
		return []model.Finding{notAssessed("HRD009")}
	}
	// Other (world) read/write/execute bits.
	if mode&0o007 != 0 {
		f := catalog.Get("HRD009").Finding()
		f.Resource = dockerSockPath
		f.Evidence = dockerSockPath + " has mode " + ff.Mode + " — world-accessible bits are set (other r/w/x)"
		f.Fix = model.Fix{
			Summary: "Restrict /var/run/docker.sock to owner root and group docker (0660). Remove world-accessible bits.",
			Commands: []string{
				"chmod 660 /var/run/docker.sock",
				"chown root:docker /var/run/docker.sock",
			},
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("HRD009").Pass("/var/run/docker.sock permissions are appropriately restricted.")}
}
