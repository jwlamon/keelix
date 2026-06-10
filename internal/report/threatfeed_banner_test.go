package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jakelamon/keelix/internal/model"
	"github.com/jakelamon/keelix/internal/threatfeed"
)

func baseResult(now time.Time) *model.Result {
	return &model.Result{
		Target:       "example.com",
		ScannedAt:    now,
		Version:      "test",
		Score:        80,
		Rating:       "GREEN",
		ScoringModel: "v2",
		SubScores:    []model.GroupScore{{Group: model.GroupExposure, Score: 80}},
	}
}

func TestTerminalStaleBannerShown(t *testing.T) {
	// 60 days after the snapshot → stale → banner present.
	now := threatfeed.SnapshotDate().Add(60 * 24 * time.Hour)
	var buf bytes.Buffer
	if err := Terminal(&buf, baseResult(now), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "threat data is") || !strings.Contains(out, "days old") {
		t.Errorf("expected staleness banner in output:\n%s", out)
	}
	if !strings.Contains(out, "Threat data:") {
		t.Errorf("expected methodology note in output:\n%s", out)
	}
}

func TestTerminalFreshNoBanner(t *testing.T) {
	// 1 day after the snapshot → fresh → no banner, but methodology note present.
	now := threatfeed.SnapshotDate().Add(24 * time.Hour)
	var buf bytes.Buffer
	if err := Terminal(&buf, baseResult(now), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "may understate current risk") {
		t.Errorf("did not expect staleness banner for fresh data:\n%s", out)
	}
	if !strings.Contains(out, "Threat data:") {
		t.Errorf("expected methodology note even when fresh:\n%s", out)
	}
}

func TestMarkdownAndHTMLCarrySnapshotDate(t *testing.T) {
	now := threatfeed.SnapshotDate().Add(24 * time.Hour)
	r := baseResult(now)
	snap := threatfeed.SnapshotDate().Format("2006-01-02")

	var md bytes.Buffer
	if err := Markdown(&md, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), snap) {
		t.Errorf("markdown methodology missing snapshot date %q", snap)
	}

	var h bytes.Buffer
	if err := HTML(&h, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.String(), snap) {
		t.Errorf("html methodology missing snapshot date %q", snap)
	}
}
