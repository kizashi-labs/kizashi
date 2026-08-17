package handlers

import (
	"bytes"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 本文が「無い」ことと「壊れている」ことの区別。
//
// c.ShouldBindJSON はどちらも err で返します。いくつかのハンドラはそれを
// 同じものとして扱い、既定値を入れて処理を続けていました:
//
//	if err := c.ShouldBindJSON(&req); err != nil {
//		req.Reason = "手動隔離"
//	}
//
// 本文を省略した呼び出しに既定値を入れるのは正しい動きです。壊れた本文に
// 既定値を入れるのは違います。送信側の不具合で本文が壊れているとき、
// 端末は隔離され、理由は「手動隔離」と記録されます。実際には誰も
// そう言っていません。おとりへのアクセス記録では、送信元 IP まで
// 192.168.1.100 と作られていました。

func TestAnAbsentBodyAndABrokenBodyAreDifferent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tc := range []struct {
		name     string
		body     string
		wantOK   bool
		wantCode int
		wantVal  string
	}{
		{"本文が無い", "", true, 200, ""},
		{"本文が正しい", `{"reason":"侵害の疑い"}`, true, 200, "侵害の疑い"},
		{"本文が壊れている", `{"reason":`, false, 400, ""},
		{"本文が JSON ですらない", `not json at all`, false, 400, ""},
		{"型が違う", `{"reason":123}`, false, 400, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/x", bytes.NewBufferString(tc.body))
			c.Request.Header.Set("Content-Type", "application/json")

			var req struct {
				Reason string `json:"reason"`
			}
			got := OptionalBody(c, &req)

			if got != tc.wantOK {
				t.Fatalf("OptionalBody = %v, want %v", got, tc.wantOK)
			}
			if req.Reason != tc.wantVal {
				t.Errorf("reason = %q, want %q", req.Reason, tc.wantVal)
			}
			if !tc.wantOK {
				if w.Code != tc.wantCode {
					t.Errorf("status = %d, want %d。壊れた本文で既定値のまま続けると、"+
						"誰も言っていない理由が記録に残ります", w.Code, tc.wantCode)
				}
				if !strings.Contains(w.Body.String(), "既定値では続けません") {
					t.Errorf("なぜ断ったのかが応答に書かれていません: %s", w.Body.String())
				}
			}
		})
	}
}

// トークンを作るバイト列は crypto/rand から取ること。
//
// はじめこの検査は「rand.Read の戻り値を捨てていないこと」でした。捨てて
// いる箇所が4つ見つかったので直しかけましたが、間違いでした。crypto/rand.Read
// は Go 1.24 以降エラーを返しません（取得できないときは panic します）。
// つまりエラー分岐を書いても到達しません。到達しない検査を残さないのは
// この取り組みの規則そのものなので、書いたものを戻しました。
//
// 本当に確かめる価値があるのは、その rand がどちらの rand かです。
// math/rand で作った32バイトは、見た目は同じで、推測できます。
func TestTokenBytesComeFromCryptoRand(t *testing.T) {
	var bad []string
	fset := token.NewFileSet()
	err := filepath.Walk("../..", func(path string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/gen/") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return perr
		}
		mathRand := false
		for _, im := range f.Imports {
			if im.Path.Value == `"math/rand"` {
				mathRand = true
			}
		}
		if !mathRand {
			return nil
		}
		// math/rand it is — allowed only where randomness is a sampling
		// choice, not a secret. internal/ml draws feature subsets.
		if !strings.Contains(filepath.ToSlash(path), "/ml/") {
			bad = append(bad, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, p := range bad {
		t.Errorf("%s が math/rand を使っています。トークンや鍵に使うと推測できます。"+
			"標本抽出のためなら、このテストに理由付きで許可を足してください", p)
	}
}

// 走査が形を見分けられること。0件は「無い」と「探せていない」の
// どちらでもあり得ます。
func TestTheRandImportScanCanSeeBothKinds(t *testing.T) {
	fset := token.NewFileSet()
	for _, tc := range []struct {
		name string
		src  string
		want bool
	}{
		{"math/rand", "package p\nimport \"math/rand\"\n", true},
		{"crypto/rand", "package p\nimport \"crypto/rand\"\n", false},
		{"どちらでもない", "package p\nimport \"fmt\"\n", false},
	} {
		f, err := parser.ParseFile(fset, "x.go", tc.src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		got := false
		for _, im := range f.Imports {
			if im.Path.Value == `"math/rand"` {
				got = true
			}
		}
		if got != tc.want {
			t.Errorf("%s: %v (want %v)", tc.name, got, tc.want)
		}
	}
}
