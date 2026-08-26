package api

// commercialHandlers is the open source edition's empty set.
//
// ─── 公開版向けの差し替え（scripts/public-snapshot/overlay） ──────────────
//
// 本流の同名ファイルは、有償版だけが持つハンドラのフィールドを並べる。公開版には
// その実装（internal/billing, internal/mdm, internal/saml, …）が無いので、
// フィールドごと空にする。
//
// **これが router.go の全文コピーを overlay から無くすための片側。** もう片側は
// routes_commercial.go（登録の呼び出し）。両方が揃うと router.go は版によらず
// 同一になり、追随作業そのものが無くなる。
type commercialHandlers struct{}
