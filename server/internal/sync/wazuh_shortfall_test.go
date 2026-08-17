package sync

import "testing"

// 一部の端末だけ届かなかったとき、合計だけを返さないこと。
//
// 以前は端末ごとの取得に失敗すると continue して、最後に件数だけを返して
// いました。「500件を同期しました」は、届かなかった端末があっても同じ文です。
// 脆弱性が0件の端末と、問い合わせられなかった端末の区別が付きません。
func TestAPartialSyncIsNotReportedAsAWholeOne(t *testing.T) {
	for _, tc := range []struct {
		name           string
		synced, failed int
		wantErr        bool
	}{
		{"全部届いた", 500, 0, false},
		{"1台届かなかった", 499, 1, true},
		{"全部届かなかった", 0, 12, true},
		{"何も無かった", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := syncShortfall(tc.synced, tc.failed)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error: %v", err, tc.wantErr)
			}
			if err == nil {
				return
			}
			// 何台落ちたのかと、何件は入ったのかの両方が要ります。
			// 片方だけだと、呼び出し側は再同期の判断ができません。
			for _, want := range []string{"取得できませんでした", "同期済み"} {
				if !contains(err.Error(), want) {
					t.Errorf("%q が %q を含んでいません", err.Error(), want)
				}
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
