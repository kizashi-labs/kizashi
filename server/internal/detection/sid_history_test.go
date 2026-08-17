package detection

import "testing"

// T1134.005 — SID-History の付与 (Security 4765/4766)。
//
// このルールは 2026-08-14 まで**入れられなかった**。第 1 波 (migration 384) の候補
// 6 件のうち唯一外したのがこれで、理由はルールの書き方ではなく **値がワイヤに
// 乗っていなかった**ことにある:
//
//	1. agent の購読述語が 4624/4625/4634/4672 だけで 4765/4766 を含まない
//	2. auth_parse.go の switch が未知の EventID を default で捨てる
//	3. AuthEvent がワイヤ上に EventID を持たない
//
// **「フィールド解決の検査は通るが値が永久に来ない」**——最も見つけにくい壊れ方である。
// だからこのファイルの本命は「ルールが書けているか」ではなく、
// **エージェントが実際に出す形のイベントで発火するか**の方である。
//
// 供給側 (agent の parse / 購読述語) は agent モジュール側のテストが押さえる:
//
//	agent/internal/platform/windows/auth_parse_test.go   4765/4766 を捨てないこと
//	agent/internal/platform/windows/auth_query_test.go   購読述語に入っていること
//
// ここはその続きで、ingestion が出す平坦化マップの形から先を確かめる。

// authFlat は internal/ingestion/handler.go の EVENT_TYPE_AUTH 分岐が作る
// マップと同じ形。ここを本物とずらすと、テストだけが緑になる。
func authFlat(eventID float64, username string, success bool) map[string]interface{} {
	m := map[string]interface{}{
		"type":           "auth",
		"username":       username,
		"action":         "privilege",
		"success":        success,
		"source_ip":      "10.0.0.5",
		"auth_method":    "unknown",
		"failure_reason": "",
	}
	if eventID != 0 {
		m["event_id"] = eventID
	}
	return m
}

func firedSIDHistory(f []EvalFinding) bool {
	return firedTitleContains(f, "SID-History Added to Account")
}

func TestT1134_005_SIDHistoryFiresOnAgentShapedEvent(t *testing.T) {
	for _, c := range []struct {
		id   float64
		why  string
		succ bool
	}{
		{4765, "SID-History の付与に成功", true},
		{4766, "付与の試行が失敗（未遂も痕跡として残す）", false},
	} {
		f := EvaluateEnvelope("auth", authFlat(c.id, "svc-backup", c.succ))
		if !firedSIDHistory(f) {
			t.Errorf("SID-History の付与が検知されない (%s, EventID=%v) → %v", c.why, c.id, titles(f))
		}
	}
}

// TestT1134_005_QuietOnOrdinaryLogon は、開けたのが 4765/4766 **だけ**であることを
// 固定する。
//
// ログオン系 (4624/4625/4634/4672) の EventID を Sigma に開けると、curate が
// SupportedSigmaFields() を見て enabled にしている SigmaHQ の `service: security`
// ルール群が一斉に生き返る。**ログオンのたびに鳴る形**が混ざるので、開けるなら
// アラート量の実測 (FP ソーク) が要る。本 PR では測っていないので開けていない。
//
// 許可リスト (alert_pipeline.go の sigmaExposedAuthEventIDs) を黙って広げると
// この判断を通らずに変わってしまうため、ここで固定する。
func TestT1134_005_QuietOnOrdinaryLogon(t *testing.T) {
	// 対照。4765 が鳴らないなら、以下の沈黙チェックは何も確かめていない。
	if !firedSIDHistory(EvaluateEnvelope("auth", authFlat(4765, "svc-backup", true))) {
		t.Fatal("対照が効いていない: SID-History の付与が鳴らないので、" +
			"以下の沈黙チェックが通っても意味が無い")
	}

	for _, c := range []struct {
		id  float64
		why string
	}{
		{4624, "ログオン成功"},
		{4625, "ログオン失敗"},
		{4634, "ログオフ"},
		{4672, "特権の付与（管理者ログオンのたびに出る）"},
	} {
		flat := authFlat(c.id, "tanaka", c.id != 4625)
		if _, exposed := flat["EventID"]; exposed {
			t.Fatalf("平坦化マップに EventID が直接入っている——別名層の検査にならない")
		}
		addPipelineSigmaAliases(flat)
		if v, ok := flat["EventID"]; ok {
			t.Errorf("ログオン系 %v (%s) が Sigma の EventID に露出している (=%v)。"+
				"許可リストを広げるなら、SigmaHQ の service: security ルール群が"+
				"一斉に生き返る分のアラート量を FP ソークで測ってからにすること",
				c.id, c.why, v)
		}
	}
}

// TestT1134_005_AliasNeedsAnAuthEvent は、別名付与が auth イベントに限定されて
// いることを固定する。
//
// event_id は wmi_activity イベント (5858/5861) も持っており、そちらは
// SupportedSigmaFields() のキッチンシンクにも入っている。auth で絞っていないと、
// 無関係なイベント種別に Security ログの EventID を与えてしまう。
func TestT1134_005_AliasNeedsAnAuthEvent(t *testing.T) {
	wmiLike := map[string]interface{}{
		"type":       "wmi_activity",
		"event_id":   float64(4765), // わざと同じ値にする
		"event_type": "WmiBindingEvent",
	}
	addPipelineSigmaAliases(wmiLike)
	if v, ok := wmiLike["EventID"]; ok {
		t.Errorf("auth 以外のイベントに Security ログの EventID を与えている (=%v)——"+
			"auth_method で絞る条件が外れている", v)
	}
}

// TestT1134_005_AccountManagementIsNotABruteForceSignal は、4766 (付与失敗) が
// ブルートフォース検知器の失敗カウンタに入らないことを固定する。
//
// ★ これは実機事故の再発防止である。2026-08-05 に 4648 (明示的資格情報での
// ログオン**試行**) を「ログオン成功」として取り込んでおり、
// PrincipalContext.ValidateCredentials が失敗のたびに 4625 と 4648 を両方出すため、
// AuthAttackScorer が「失敗の連続のあとの成功」を見て severity 8 の
// 「アカウント侵害」アラートを**存在しないアカウントに対して**捏造していた。
//
// 4766 は success=false を持つので、素通しすると authSucceeded() が失敗ログオンと
// して数え、同じ形の捏造が起きる。auth_parse.go の 4648 のコメントが
// 「復活させるなら AuthAttackScorer 側の除外もセットで要る」と書いていた、その
// 除外がこれにあたる。
func TestT1134_005_AccountManagementIsNotABruteForceSignal(t *testing.T) {
	// 対照。ログオン失敗がアカウント操作と判定されるなら、以下の検査は無意味。
	if isAccountManagementAuth(authFlat(4625, "tanaka", false)) {
		t.Fatal("対照が効いていない: ログオン失敗をアカウント操作と判定している")
	}
	if isAccountManagementAuth(authFlat(0, "tanaka", false)) {
		t.Fatal("対照が効いていない: EventID の無い auth イベント（非 Windows）を" +
			"アカウント操作と判定している")
	}

	for _, id := range []float64{4765, 4766} {
		if !isAccountManagementAuth(authFlat(id, "svc-backup", id == 4765)) {
			t.Errorf("EventID=%v がブルートフォース計数から除外されていない——"+
				"4766 は success=false なので、失敗ログオンとして数えられ、"+
				"偽の「アカウント侵害」アラートの材料になる", id)
		}
	}
}
