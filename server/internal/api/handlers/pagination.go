package handlers

// 一覧の頁送りの補完。
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。**
// これまで `quarantine_playbook_validate_test.go` の中に `clampPage` /
// `clampPerPage` / `quarantineOffset` という写しが置いてあり、試されて
// いたのは写しの方だけでした。ハンドラ側は同じ4行が18か所に散っていて、
// **そのうち2か所には上限の行がありませんでした。**
//
// 実測 (2026-08-12)。`/api/v1/vulnerabilities`:
//
//	per_page 指定なし → 200 / 50件 / total=120
//	per_page=0        → 200 / **0件** / total=120
//	per_page=abc      → 200 / **0件** / total=120
//	per_page=-1       → **500**「脆弱性一覧の取得に失敗しました」
//	per_page=100000   → 200 / **120件**（上限なし）
//
// `/training/campaigns/:id/results` はさらに静かで、`per_page=-1` が
// **200 の 0 件**で返ります（`LIMIT must not be negative` は警告ログに
// 落ちるだけです）。total は 80 と出るので、画面には「80件あるのに
// 1件も表示されない」が並びます。
//
// **0 件と「数えられなかった」が同じ姿になるのがここでの害です。**

// clampPage は 1 未満のページ番号を 1 に寄せます。
//
// 負のページをそのまま通すと OFFSET が負になり、Postgres が問い合わせ
// ごと拒否します。**一覧が丸ごとエラーになります。**
func clampPage(page int) int {
	if page < 1 {
		return 1
	}
	return page
}

// clampPerPage は範囲外の件数を既定値に戻します。
//
// 0 や負や桁違いを**既定に戻す**のは、0 をそのまま通すと 0 件返り、
// 「該当なし」と見分けが付かなくなるからです。上限を設けるのは、
// `per_page=100000` が実質「全件返せ」になるからです。
func clampPerPage(perPage, def, max int) int {
	if perPage < 1 || perPage > max {
		return def
	}
	return perPage
}

// pageOffset はページ番号と件数から OFFSET を出します。
func pageOffset(page, perPage int) int {
	return (page - 1) * perPage
}

// clampPageParams は上の3つをまとめたものです。ハンドラはこれを呼びます。
func clampPageParams(page, perPage, def, max int) (int, int, int) {
	page = clampPage(page)
	perPage = clampPerPage(perPage, def, max)
	return page, perPage, pageOffset(page, perPage)
}
