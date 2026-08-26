package detection

import (
	"context"
	"strings"
	"testing"
)

// migration 394/395/406 が seed するテンプレートの条件。**ここに実物を置く**のは、
// 「テンプレートを有効化したら意図どおりのホストだけが抑制される」ことが
// このテストの主題だからです。テンプレートは既定で無効なので、壊れていても
// 有効化した瞬間まで誰も気づきません。
const (
	tmplContainerFleet = `(?i)^(k8s-node-|kube-|ci-runner-|.*-build-|docker-host-|containerd-)`
	tmplPsExecMgmt     = `(?i)^(mgmt-|jump-|bastion-|admin-)`
	tmplBITSEndpoint   = `(?i)(-ws-|-laptop-|-desktop-)|^(ws-|desktop-)`
	tmplTunnelDev      = `(?i)(-dev-|-test-|-staging-)|^(dev-|test-)`
	tmplRcloneBackup   = `(?i)(-backup-|-bkp-|-job-)|^(backup-|bkp-)`
)

// **これが本題です。** hostname_regex を誰も読んでいなかったとき、
// このテンプレートは「rule_name だけを条件に持つルール」として評価され、
// prod を含む全ホストで T1609 を抑制していました。既定が is_active=FALSE
// だったので実害は出ませんでしたが、運用手順どおり有効化した瞬間に効きます。
func TestSuppression_HostnameRegex_TemplateDoesNotSuppressProd(t *testing.T) {
	m := newMatcher(t, SuppressionRule{
		ID: "tmpl-330", Name: "[テンプレート] Container Administration",
		RuleName:      "Container Administration",
		HostnameRegex: tmplContainerFleet,
	})

	cases := []struct {
		hostname string
		want     bool
	}{
		{"k8s-node-07", true},
		{"KUBE-Worker-3", true}, // (?i)
		{"ci-runner-12", true},
		{"tokyo-build-01", true}, // `.*-build-`
		{"docker-host-a", true},
		{"prod-db-01", false},      // ★ prod は抑制しない
		{"prod-k8s-node-1", false}, // ★ アンカー: 接頭辞でなければ当たらない
		{"web-01", false},
	}
	for _, c := range cases {
		alert := &StoredAlert{
			RuleName: "Container Administration Command Execution",
			Hostname: c.hostname, Severity: 5,
		}
		got, _, _ := m.IsSuppressed(alert, SuppressionContext{})
		if got != c.want {
			t.Errorf("hostname=%q: 抑制 = %v, want %v", c.hostname, got, c.want)
		}
	}
}

// 他のテンプレートも、seed された式そのままで「意図した群だけ」に当たること。
func TestSuppression_HostnameRegex_SeededTemplates(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		match   []string
		nomatch []string
	}{
		{"PsExec 管理群", tmplPsExecMgmt,
			[]string{"mgmt-01", "Jump-Host-2", "bastion-a", "admin-tools-1"},
			[]string{"prod-db-01", "app-mgmt-01"}},
		{"BITS 端末群", tmplBITSEndpoint,
			[]string{"jp-ws-0012", "corp-laptop-9", "ws-001", "desktop-77"},
			[]string{"prod-db-01", "srv-bits-01"}},
		{"トンネル dev/test", tmplTunnelDev,
			[]string{"app-dev-01", "x-staging-2", "dev-box", "test-01"},
			[]string{"prod-db-01", "production-01"}},
		{"Rclone バックアップ", tmplRcloneBackup,
			[]string{"srv-backup-01", "n-bkp-2", "batch-job-3", "backup-01"},
			[]string{"prod-db-01", "app-01"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMatcher(t, SuppressionRule{
				ID: "t", Name: c.name, RuleName: "Rule", HostnameRegex: c.pattern,
			})
			for _, h := range c.match {
				a := &StoredAlert{RuleName: "Rule X", Hostname: h, Severity: 5}
				if supp, _, _ := m.IsSuppressed(a, SuppressionContext{}); !supp {
					t.Errorf("%q は抑制されるべき", h)
				}
			}
			for _, h := range c.nomatch {
				a := &StoredAlert{RuleName: "Rule X", Hostname: h, Severity: 5}
				if supp, _, _ := m.IsSuppressed(a, SuppressionContext{}); supp {
					t.Errorf("%q は抑制されてはならない", h)
				}
			}
		})
	}
}

// コンパイルできない式は**抑制しない**。ホスト条件を無視して先へ進むと、
// rule_name だけが残って全ホスト抑制になる——最悪の外し方。
//
// ★ 壊れた式が「唯一の条件」なら、そのルールは適用対象にすらしない
// （ClassifySuppression が catch-all と判定する）。他に絞り込みがあれば
// キャッシュには載るが、**matches() が必ず false を返す**。
// どちらの経路でも抑制は起きない、というのがここで留めたいこと。
func TestSuppression_HostnameRegex_InvalidNeverSuppresses(t *testing.T) {
	alert := &StoredAlert{RuleName: "Container Administration Command Execution",
		Hostname: "k8s-node-07", Severity: 5}

	// (1) 壊れた式だけのルールは、そもそもキャッシュに載らない。
	onlyBad := SuppressionRule{ID: "bad1", Name: "壊れた式だけ", HostnameRegex: `^(k8s-node-`}
	m1 := NewSuppressionMatcher(&fakeSuppLoader{rules: []SuppressionRule{onlyBad}})
	m1.RefreshNow(context.Background())
	if m1.Count() != 0 {
		t.Errorf("壊れた式だけのルールがキャッシュに載っている (count=%d)——"+
			"適用しないものを「有効なルール」として数えてはならない", m1.Count())
	}

	// (2) 他に絞り込みがあれば載る。**それでも抑制はしない。**
	withName := SuppressionRule{
		ID: "bad2", Name: "壊れた式 + ルール名",
		RuleName: "Container Administration", HostnameRegex: `^(k8s-node-`,
	}
	m2 := newMatcher(t, withName)
	if supp, _, _ := m2.IsSuppressed(alert, SuppressionContext{}); supp {
		t.Error("壊れた式のルールが抑制している——" +
			"ホスト条件が無視され、rule_name だけで全ホストに当たっている")
	}

	// loader を経ない経路でも matches() が拒むこと（二重の防御）。
	if m2.matches(withName, alert, SuppressionContext{}) {
		t.Error("matches() が壊れた式のルールを一致させている")
	}
}

// hostname と hostname_regex の両方が書かれていれば AND。片方だけを見て
// 通してはいけない。
func TestSuppression_HostnameRegex_CombinesWithHostname(t *testing.T) {
	m := newMatcher(t, SuppressionRule{
		ID: "both", Name: "両方", RuleName: "Rule",
		Hostname: "k8s", HostnameRegex: `-node-0[1-9]$`,
	})
	cases := []struct {
		hostname string
		want     bool
	}{
		{"k8s-node-07", true},
		{"k8s-node-70", false}, // regex が外れる
		{"gke-node-07", false}, // hostname 部分一致が外れる
	}
	for _, c := range cases {
		a := &StoredAlert{RuleName: "Rule X", Hostname: c.hostname, Severity: 5}
		if got, _, _ := m.IsSuppressed(a, SuppressionContext{}); got != c.want {
			t.Errorf("hostname=%q: 抑制 = %v, want %v", c.hostname, got, c.want)
		}
	}
}

// 全ホストに当たる式は「絞り込み」として数えない。rule_name だけの
// ルールと同じ広さなのに、hostname_regex が書いてあるせいで
// narrow に見える——という誤解を防ぐ。
func TestClassifySuppression_HostnameRegexBreadth(t *testing.T) {
	cases := []struct {
		name    string
		rule    SuppressionRule
		want    SuppressionBreadth
		wantWhy string
	}{
		{"テンプレートは narrow",
			SuppressionRule{RuleName: "Container Administration", HostnameRegex: tmplContainerFleet},
			SuppressionNarrow, "hostname_regex"},
		// rule_name が具体的なので narrow のままだが、**絞り込みの根拠として
		// hostname_regex は数えない**。数えると「ホストを絞ってある」に見える。
		{"`.*` は絞り込みの根拠に数えない",
			SuppressionRule{RuleName: "Container Administration", HostnameRegex: `.*`},
			SuppressionNarrow, "rule_name"},
		{"`.*` だけなら catch-all",
			SuppressionRule{HostnameRegex: `.*`},
			SuppressionCatchAll, "絞り込みにならない"},
		{"`^` だけなら catch-all",
			SuppressionRule{HostnameRegex: `^`},
			SuppressionCatchAll, "絞り込みにならない"},
		{"壊れた式だけなら catch-all 扱い（適用しない）",
			SuppressionRule{HostnameRegex: `^(k8s-`},
			SuppressionCatchAll, "コンパイルできない"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := ClassifySuppression(c.rule)
			if got != c.want {
				t.Errorf("breadth = %v, want %v (理由: %s)", got, c.want, why)
			}
			if c.wantWhy != "" && !strings.Contains(why, c.wantWhy) {
				t.Errorf("理由に %q が含まれるべき: %s", c.wantWhy, why)
			}
		})
	}
}
