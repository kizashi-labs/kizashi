package handlers

import (
	"testing"
)

// ページの切り詰め。
//
// **`internal/store` の検査に写しが置いてありましたが、値が違いました。**
// 写しは「既定 20 / 200 超は 200 に丸める」と言い、本物は
// 「既定 50 / 範囲外は 50 に戻す」です。**製品に無い約束を確かめていた**
// ことになります。
//
// 切り詰めは1箇所だけにします（`store.List` は切り詰めません）——
// 2箇所に置くと、片方を直したときにもう片方が残ります。

func TestNotificationPageClamp(t *testing.T) {
	cases := []struct {
		name                  string
		page, perPage         int
		wantPage, wantPerPage int
		wantOffset            int
	}{
		{"既定", 1, 50, 1, 50, 0},
		{"2ページ目", 2, 50, 2, 50, 50},
		// **0 ページ目は 1 ページ目です。** 負のオフセットは Postgres が
		// 拒否するので、通すと一覧が丸ごとエラーになります。
		{"ページが 0", 0, 50, 1, 50, 0},
		{"ページが負", -5, 50, 1, 50, 0},
		// **per_page が 0 だと 0 件返ります。** 「履歴が無い」と
		// 見分けが付きません。
		{"per_page が 0", 1, 0, 1, 50, 0},
		{"per_page が負", 1, -1, 1, 50, 0},
		{"per_page が大きすぎる", 1, 5000, 1, 50, 0},
		{"上限ちょうど", 1, 200, 1, 200, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, perPage, offset := clampNotificationPage(tc.page, tc.perPage)
			if page != tc.wantPage || perPage != tc.wantPerPage || offset != tc.wantOffset {
				t.Errorf("clampNotificationPage(%d, %d) = (%d, %d, %d), want (%d, %d, %d)",
					tc.page, tc.perPage, page, perPage, offset,
					tc.wantPage, tc.wantPerPage, tc.wantOffset)
			}
		})
	}
}

// オフセットが負にならないこと。**Postgres は負の OFFSET を拒否します。**
func TestNotificationOffsetIsNeverNegative(t *testing.T) {
	for _, page := range []int{-1000, -1, 0, 1} {
		if _, _, offset := clampNotificationPage(page, 50); offset < 0 {
			t.Errorf("page=%d で offset=%d。**一覧が丸ごとエラーになります**",
				page, offset)
		}
	}
}
