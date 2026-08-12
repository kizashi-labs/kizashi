package detection

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The alert title is the identity every downstream consumer groups on:
// detectionmetrics.TopFalsePositiveRules groups false positives by title, the
// FP-soak scorecard lines a run up against its baseline by title, and the title
// is the unit an analyst means when they say "suppress this rule".
//
// The rate detectors used to interpolate the observed count into the title
// ("...が30秒内に141個のファイルを破壊的操作"), so one detector produced a new
// identity on almost every firing. A single FP-soak run recorded `find` as six
// separate rules (110/112/119/123/133/141 files) and the next run produced three
// different ones (140/179/197) with no overlap at all — the baseline could not
// match anything and the regression gate was meaningless.
//
// The magnitude belongs in the description, which carries it in every case.
// These tests pin the split: fire each detector twice at very different
// magnitudes and require one identical title.

// fireBurst drives the file-burst detector past its threshold with n files and
// returns the one title every alert carried, plus the last description.
//
// A single burst can raise more than one alert: the detector deliberately lets a
// materially larger burst escalate through the dedup window. Those re-fires see
// a bigger count, which is exactly the case that used to mint a second rule, so
// requiring one distinct title across all of them is the stronger assertion.
func fireBurst(t *testing.T, n int) (title, desc string) {
	t.Helper()
	d := newFileBurstScorer()
	base := time.Unix(1_700_000_000, 0)
	titles := map[string]bool{}
	var gotDesc string
	var count int
	for i := 0; i < n; i++ {
		for _, m := range d.Observe("agent-1", "go", fmt.Sprintf("/src/f%d.o", i), "modify", base) {
			titles[m.Title] = true
			gotDesc = m.Description
			count++
		}
	}
	if count == 0 {
		t.Fatalf("n=%d: 発火しませんでした", n)
	}
	if len(titles) != 1 {
		t.Fatalf("n=%d: %d 件のアラートが %d 種類のタイトルを出しました: %v",
			n, count, len(titles), titles)
	}
	for k := range titles {
		title = k
	}
	return title, gotDesc
}

func TestFileBurstTitleIsStableAcrossMagnitudes(t *testing.T) {
	small, desc := fireBurst(t, fileBurstMinFiles)
	large, _ := fireBurst(t, fileBurstMinFiles*3)

	if small != large {
		t.Errorf("件数でタイトルが変わりました:\n  %q\n  %q", small, large)
	}
	if strings.Contains(small, fmt.Sprint(fileBurstMinFiles)+"個") {
		t.Errorf("タイトルに観測件数が残っています: %q", small)
	}
	// The magnitude must not be lost — it belongs in the description. (Both
	// bursts alert on the file that crosses the threshold, so both report
	// exactly fileBurstMinFiles here; larger counts appear in production when a
	// process keeps churning through the dedup window and the next alert fires
	// with everything still inside the 30s window.)
	if !strings.Contains(desc, fmt.Sprint(fileBurstMinFiles)) {
		t.Errorf("説明文に観測件数が入っていません: %q", desc)
	}
}

func TestNetworkScanTitleIsStableAcrossMagnitudes(t *testing.T) {
	fire := func(ports int) string {
		d := newNetworkScanDetector()
		base := time.Unix(1_700_000_000, 0)
		var got []string
		for p := 1; p <= ports; p++ {
			for _, m := range d.Observe("agent-1", "nmap", "10.0.0.9", p, true, base) {
				got = append(got, m.Title)
			}
		}
		if len(got) == 0 {
			t.Fatalf("ports=%d: 発火しませんでした", ports)
		}
		return got[0]
	}
	if a, b := fire(40), fire(400); a != b {
		t.Errorf("ポート数でタイトルが変わりました:\n  %q\n  %q", a, b)
	}
}

func TestLateralFanoutTitleIsStableAcrossMagnitudes(t *testing.T) {
	fire := func(hosts int) string {
		d := newLateralFanoutScorer()
		base := time.Unix(1_700_000_000, 0)
		var got []string
		for i := 1; i <= hosts; i++ {
			for _, m := range d.Observe("agent-1", fmt.Sprintf("10.0.%d.%d", i/250, i%250), 3389, base) {
				got = append(got, m.Title)
			}
		}
		if len(got) == 0 {
			t.Fatalf("hosts=%d: 発火しませんでした", hosts)
		}
		return got[0]
	}
	if a, b := fire(20), fire(200); a != b {
		t.Errorf("宛先数でタイトルが変わりました:\n  %q\n  %q", a, b)
	}
}

func TestExfilVolumeTitleIsStableAcrossMagnitudes(t *testing.T) {
	fire := func(mb int64) string {
		d := newExfilVolumeDetector()
		base := time.Unix(1_700_000_000, 0)
		var got []string
		for i := int64(0); i < mb; i++ {
			for _, m := range d.Observe("agent-1", "203.0.113.9", 1<<20, base) {
				got = append(got, m.Title)
			}
		}
		if len(got) == 0 {
			t.Fatalf("mb=%d: 発火しませんでした", mb)
		}
		return got[0]
	}
	// humanBytes() rendered the running total into the title, so "700 MB" and
	// "2.0 GB" used to be two different rules for one destination.
	if a, b := fire(700), fire(2048); a != b {
		t.Errorf("送信量でタイトルが変わりました:\n  %q\n  %q", a, b)
	}
}

func TestDNSTunnelTitleIsStableAcrossMagnitudes(t *testing.T) {
	fire := func(subs int) string {
		d := newDNSTunnelAggregator()
		base := time.Unix(1_700_000_000, 0)
		var got []string
		for i := 0; i < subs; i++ {
			for _, m := range d.Observe("agent-1", fmt.Sprintf("s%d.tunnel.example.com", i), base) {
				got = append(got, m.Title)
			}
		}
		if len(got) == 0 {
			t.Fatalf("subs=%d: 発火しませんでした", subs)
		}
		return got[0]
	}
	if a, b := fire(40), fire(400); a != b {
		t.Errorf("サブドメイン数でタイトルが変わりました:\n  %q\n  %q", a, b)
	}
}

// Guard the whole family at once: no runtime-detector title may contain a digit
// run that came from the observation. Window sizes are constants and are
// allowed, so this checks the specific shape the bug took — a number
// immediately followed by a counting suffix.
func TestRuntimeDetectorTitlesCarryNoObservedCount(t *testing.T) {
	title, _ := fireBurst(t, fileBurstMinFiles*2)
	for _, bad := range []string{"個の", "回の", "種の", "段の"} {
		if idx := strings.Index(title, bad); idx > 0 {
			prev := title[:idx]
			if len(prev) > 0 && prev[len(prev)-1] >= '0' && prev[len(prev)-1] <= '9' {
				t.Errorf("タイトルに観測値が埋め込まれています (%q の直前が数字): %q", bad, title)
			}
		}
	}
}
