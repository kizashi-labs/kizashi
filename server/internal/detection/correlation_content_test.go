package detection

import (
	"strings"
	"testing"
)

func TestBuildCorrelationIncidentContent_SingleTechnique(t *testing.T) {
	title, desc, sev := BuildCorrelationIncidentContent("host-a", []string{"T1059"}, 5)

	if sev != 7 {
		t.Errorf("単一テクニックの severity は 7 を期待、got %d", sev)
	}
	if !strings.Contains(title, "反復アラート") {
		t.Errorf("単一テクニックのタイトルは反復アラート表記を期待、got %q", title)
	}
	if !strings.Contains(title, "T1059") || !strings.Contains(title, "host-a") {
		t.Errorf("タイトルにテクニックとホストを含むべき、got %q", title)
	}
	if !strings.Contains(title, "5件") {
		t.Errorf("タイトルにアラート件数を含むべき、got %q", title)
	}
	if !strings.Contains(desc, "T1059") {
		t.Errorf("説明にテクニックを含むべき、got %q", desc)
	}
}

func TestBuildCorrelationIncidentContent_MultiTechniqueKillChain(t *testing.T) {
	techs := []string{"T1003", "T1021.002", "T1055", "T1059"}
	title, desc, sev := BuildCorrelationIncidentContent("host-b", techs, 12)

	// 6 + 4 techniques = 10 (capped).
	if sev != 10 {
		t.Errorf("4テクニックの severity は 10 を期待、got %d", sev)
	}
	if !strings.Contains(title, "多段攻撃の疑い") {
		t.Errorf("複数テクニックのタイトルは多段攻撃の疑いを期待、got %q", title)
	}
	if !strings.Contains(title, "4 戦術") {
		t.Errorf("タイトルに戦術数を含むべき、got %q", title)
	}
	for _, tq := range techs {
		if !strings.Contains(title, tq) {
			t.Errorf("タイトルに全テクニック %s を含むべき、got %q", tq, title)
		}
	}
	if !strings.Contains(desc, "多段攻撃") {
		t.Errorf("説明に多段攻撃の記述を含むべき、got %q", desc)
	}
}

func TestBuildCorrelationIncidentContent_SeverityScalesWithBreadth(t *testing.T) {
	cases := []struct {
		n       int
		wantSev int
	}{
		{1, 7}, {2, 8}, {3, 9}, {4, 10}, {5, 10}, {8, 10},
	}
	for _, c := range cases {
		techs := make([]string, c.n)
		for i := range techs {
			techs[i] = "T10" + string(rune('0'+i))
		}
		_, _, sev := BuildCorrelationIncidentContent("h", techs, 3)
		if sev != c.wantSev {
			t.Errorf("%d テクニックの severity: want %d, got %d", c.n, c.wantSev, sev)
		}
	}
}

func TestBuildCorrelationIncidentContent_EmptyTechniques(t *testing.T) {
	// Defensive: no techniques should not panic and should not be < floor severity.
	title, _, sev := BuildCorrelationIncidentContent("h", nil, 3)
	if sev < 7 {
		t.Errorf("空テクニックでも severity は下限7以上を期待、got %d", sev)
	}
	if strings.Contains(title, "多段") {
		t.Errorf("空テクニックは多段扱いにしない、got %q", title)
	}
	if !strings.Contains(title, "不明") {
		t.Errorf("空テクニックは不明表記を期待、got %q", title)
	}
}

func TestSortedNonEmpty(t *testing.T) {
	got := sortedNonEmpty([]string{"T1059", "", "T1003", "  ", "T1021"})
	want := []string{"T1003", "T1021", "T1059"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: want %s, got %s", i, want[i], got[i])
		}
	}
}
