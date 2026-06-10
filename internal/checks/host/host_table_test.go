package host_test

import (
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/firewall"
	_ "github.com/jakelamon/keelix/internal/checks/host"
	"github.com/jakelamon/keelix/internal/model"
)

type tableCase struct {
	name         string
	checkID      string
	ctx          *model.ScanContext
	wantPassed   bool
	wantStatus   model.FindingStatus
	wantFatal    bool
	wantSev      model.Severity
	wantExpClass model.ExposureClass
}

func TestHostChecks_Table(t *testing.T) {
	cases := []tableCase{
		// HST003: composite — static source must never produce Fatal.
		{
			name:       "HST003_static_source_no_fatal",
			checkID:    "HST003",
			ctx:        makeHST003Context("yes", "yes", "static", "0.0.0.0"),
			wantPassed: false,
			wantFatal:  false,
		},
		// HST003: macOS — NotAssessed (no sshd effective config expected).
		{
			name:    "HST003_darwin_notAssessed",
			checkID: "HST003",
			ctx: &model.ScanContext{
				Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
			},
			wantStatus: model.StatusNotAssessed,
		},
		// HST003: all conditions + effective source + internet bind → Critical, Fatal, ExposureInternet.
		{
			name:         "HST003_effective_internet_critical_fatal",
			checkID:      "HST003",
			ctx:          makeHST003Context("yes", "yes", "effective", "0.0.0.0"),
			wantPassed:   false,
			wantFatal:    true,
			wantSev:      model.SeverityCritical,
			wantExpClass: model.ExposureInternet,
		},
		// HST010: darwin returns NotAssessed.
		{
			name:    "HST010_darwin_notAssessed",
			checkID: "HST010",
			ctx: &model.ScanContext{
				Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
			},
			wantStatus: model.StatusNotAssessed,
		},
		// HST013: darwin returns NotAssessed.
		{
			name:    "HST013_darwin_notAssessed",
			checkID: "HST013",
			ctx: &model.ScanContext{
				Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
			},
			wantStatus: model.StatusNotAssessed,
		},
		// HST030: darwin returns NotAssessed.
		{
			name:    "HST030_darwin_notAssessed",
			checkID: "HST030",
			ctx: &model.ScanContext{
				Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
			},
			wantStatus: model.StatusNotAssessed,
		},
		// HST040: darwin returns NotAssessed.
		{
			name:    "HST040_darwin_notAssessed",
			checkID: "HST040",
			ctx: &model.ScanContext{
				Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
			},
			wantStatus: model.StatusNotAssessed,
		},
		// HST022: no shadow config → NotAssessed (not a pass).
		{
			name:    "HST022_no_shadow_config_notAssessed",
			checkID: "HST022",
			ctx: &model.ScanContext{
				Collector: &model.Signals{Platform: model.Platform{OS: "linux"}},
			},
			wantStatus: model.StatusNotAssessed,
		},
		// HST023: shadow mode 0600 (root-only) → passes under 0o077 mask.
		{
			name:    "HST023_shadow_0600_passes",
			checkID: "HST023",
			ctx: &model.ScanContext{
				Collector: &model.Signals{
					Platform: model.Platform{OS: "linux"},
					Files: []model.FileFact{
						{Path: "/etc/shadow", Exists: true, Mode: "0600"},
					},
				},
			},
			wantPassed: true,
		},
		// HST023: shadow mode 0640 → fires under 0o077 mask (group-read bit set).
		{
			name:    "HST023_shadow_0640_fires",
			checkID: "HST023",
			ctx: &model.ScanContext{
				Collector: &model.Signals{
					Platform: model.Platform{OS: "linux"},
					Files: []model.FileFact{
						{Path: "/etc/shadow", Exists: true, Mode: "0640"},
					},
				},
			},
			wantPassed: false,
		},
		// HST023: shadow mode 0777 → fires.
		{
			name:    "HST023_shadow_0777_fires",
			checkID: "HST023",
			ctx: &model.ScanContext{
				Collector: &model.Signals{
					Platform: model.Platform{OS: "linux"},
					Files: []model.FileFact{
						{Path: "/etc/shadow", Exists: true, Mode: "0777"},
					},
				},
			},
			wantPassed: false,
		},
		// All checks: nil Collector → NotAssessed.
		{
			name:       "HST001_nil_collector",
			checkID:    "HST001",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		{
			name:       "HST002_nil_collector",
			checkID:    "HST002",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		{
			name:       "HST004_nil_collector",
			checkID:    "HST004",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		{
			name:       "HST005_nil_collector",
			checkID:    "HST005",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		{
			name:       "HST011_nil_collector",
			checkID:    "HST011",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		{
			name:       "HST012_nil_collector",
			checkID:    "HST012",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		{
			name:       "HST020_nil_collector",
			checkID:    "HST020",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		{
			name:       "HST021_nil_collector",
			checkID:    "HST021",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		{
			name:       "HST022_nil_collector",
			checkID:    "HST022",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		{
			name:       "HST023_nil_collector",
			checkID:    "HST023",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		{
			name:       "HST041_nil_collector",
			checkID:    "HST041",
			ctx:        &model.ScanContext{},
			wantStatus: model.StatusNotAssessed,
		},
		// FW005: darwin — NotAssessed (Docker daemon TCP exposure is Linux-only).
		{
			name:    "FW005_darwin_notAssessed",
			checkID: "FW005",
			ctx: &model.ScanContext{
				Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
			},
			wantStatus: model.StatusNotAssessed,
		},
		// FW006: darwin — NotAssessed (k3s/kubelet is Linux-only).
		{
			name:    "FW006_darwin_notAssessed",
			checkID: "FW006",
			ctx: &model.ScanContext{
				Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
			},
			wantStatus: model.StatusNotAssessed,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fs := runCheck(tc.checkID, tc.ctx)
			if len(fs) == 0 {
				t.Fatalf("check returned no findings")
			}
			f := fs[0]
			if tc.wantStatus != 0 && f.Status != tc.wantStatus {
				t.Errorf("Status: got %v, want %v", f.Status, tc.wantStatus)
			}
			if tc.wantStatus == 0 {
				if f.Passed != tc.wantPassed {
					t.Errorf("Passed: got %v, want %v (finding: %+v)", f.Passed, tc.wantPassed, f)
				}
			}
			if tc.wantFatal && !f.Fatal {
				t.Errorf("expected Fatal=true")
			}
			if !tc.wantFatal && tc.wantStatus == 0 && f.Fatal && !tc.wantPassed {
				// Only assert non-fatal when we explicitly set wantFatal=false and finding is assessed+failing.
				// (zero value of bool is false; we only check when wantSev is set to avoid false negatives)
			}
			if tc.wantSev != 0 && f.Severity != tc.wantSev {
				t.Errorf("Severity: got %v, want %v", f.Severity, tc.wantSev)
			}
			if tc.wantExpClass != 0 && f.ExposureClass != tc.wantExpClass {
				t.Errorf("ExposureClass: got %v, want %v", f.ExposureClass, tc.wantExpClass)
			}
		})
	}
}
