package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc032{}) }

type svc032 struct{}

func (c *svc032) ID() string              { return catalog.Get("SVC032").ID }
func (c *svc032) Title() string           { return catalog.Get("SVC032").Title }
func (c *svc032) Group() model.CheckGroup { return catalog.Get("SVC032").Group }

func (c *svc032) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC032")}
	}
	cf, ok := configBySchema(ctx.Collector, "jenkins-config")
	if !ok {
		return []model.Finding{notAssessed("SVC032")}
	}
	if cf.Values["useSecurity"] != "false" {
		return []model.Finding{catalog.Get("SVC032").Pass("Jenkins security is enabled.")}
	}
	f := catalog.Get("SVC032").Finding()
	f.Resource = "jenkins config.xml"
	f.Evidence = "useSecurity=false"
	f.Metadata = map[string]string{"port": "8080"}
	f.Fix = model.Fix{
		Summary: "Set <useSecurity>true</useSecurity> in $JENKINS_HOME/config.xml and restart Jenkins, or run the Setup Wizard to configure an admin account.",
		Diff:    "<useSecurity>false</useSecurity>  ->  <useSecurity>true</useSecurity>",
	}
	return []model.Finding{f}
}
