package api

// ─── 公開版向けの差し替え（scripts/public-snapshot/overlay） ──────────────
//
// 公開版の commercialHandlers は空なので、fixture も空を返す。
func commercialFixture() commercialHandlers { return commercialHandlers{} }
