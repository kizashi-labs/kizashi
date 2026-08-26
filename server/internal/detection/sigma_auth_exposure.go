// sigma_auth_exposure.go — Sigma へ写してよい auth イベントIDの許可リスト。
//
// auth_attack.go から切り出してある。addPipelineSigmaAliases（alert_pipeline.go）と
// sigma_builtins.go が参照する一方、auth_attack.go は公開版が同梱しない側
// （EXCLUDE §20.4）なので、共有シンボルだけこちらに置く。
package detection

// sigmaExposedAuthEventIDs は、Sigma の `EventID` フィールドに写してよい
// auth イベントIDの許可リスト。addPipelineSigmaAliases が参照する。
//
// ログオン系(4624/4625/4634/4672)は**入れていない**。curate は
// SupportedSigmaFields() を見て SigmaHQ の `service: security` ルールを enabled に
// しており、それらに EventID を与えると `EventID: 4624` を選ぶルール群が一斉に
// 生き返る——ログオンのたびに鳴る形が混ざるので、開けるならアラート量の実測が要る。
//
// アカウント操作(4765/4766)は正常系ではほぼ発生せず、かつ T1134.005 は
// この 2 つ以外に痕跡を残さないため、開けなければ検知手段が存在しない。
var sigmaExposedAuthEventIDs = map[uint64]bool{
	4765: true,
	4766: true,
}

// accountManagementAuthEventIDs はログオンではなく**アカウント操作**を表す
// Windows Security イベントID。ブルートフォース／スプレーの計数から外す。
//
// 4765 SID-History の付与成功 / 4766 付与失敗 (T1134.005)。
//
// 4766 は success=false を持つので、素通しすると authSucceeded() が失敗ログオンと
// して数える。**失敗の連続のあとの成功を「アカウント侵害」と判定する**のがこの
// 検知器なので、ログオンでないものを混ぜると偽の侵害アラートが出る。4648 を
// 取り込んで実際にそれを起こしたのが 2026-08-05 の実機事故である
// (agent/internal/platform/windows/auth_parse.go を参照)。
var accountManagementAuthEventIDs = map[uint64]bool{
	4765: true,
	4766: true,
}

// isAccountManagementAuth reports whether an auth event is an account-management
// record rather than a logon.
func isAccountManagementAuth(flat map[string]interface{}) bool {
	id, ok := toFloat64(flat["event_id"])
	if !ok {
		return false
	}
	return accountManagementAuthEventIDs[uint64(id)]
}
