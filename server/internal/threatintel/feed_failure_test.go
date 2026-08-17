package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// フィードが落ちていることと、そのフィードに指標が無いことは別です。
//
// 以前は取得に失敗すると []IOC{}, nil を返していました。取り込み側は
// 「0件」を正常として記録するので、フィードが何日落ちていても誰も
// 気づきません。脅威インテリジェンスの取り込みで、これは最も静かな
// 壊れ方です。
func TestAFailedFeedIsNotAnEmptyFeed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"200 で中身あり", http.StatusOK, "# comment\n198.51.100.7\n", false},
		{"200 で中身なし", http.StatusOK, "", false},
		{"500", http.StatusInternalServerError, "", true},
		{"403", http.StatusForbidden, "", true},
		{"404", http.StatusNotFound, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			body, err := fetchFeedBody(context.Background(), srv.URL, "test-feed")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error: %v", err, tc.wantErr)
			}
			if tc.wantErr {
				if len(body) != 0 {
					t.Errorf("失敗したのに %d バイト返しています", len(body))
				}
				if !strings.Contains(err.Error(), "test-feed") {
					t.Errorf("どのフィードが落ちたのかが書かれていません: %v", err)
				}
			}
		})
	}
}
