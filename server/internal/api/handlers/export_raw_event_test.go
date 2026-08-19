package handlers

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	tenantcrypto "github.com/edr-platform/server/internal/crypto"
	"github.com/edr-platform/server/internal/store"
)

// エクスポートに ciphertext が出ないこと。
//
// 暗号化を有効にすると、raw_event の列は "enc:<base64>" になります。
// エクスポートはセルをそのまま CSV / JSON に書くので、**何も足さないと
// 顧客に渡す出力ファイルに暗号文が並びます。** 空にすれば今度は
// 「生データの無い行」に見えます。どちらも嘘なので、復号するか、
// 復号できなかったと書くかのどちらかにします。
//
// この検査が無いと、IsEncryptedRawEvent が false を返すようになっても
// （＝復号を素通りするようになっても）誰も気づきません。

func exportTestContext(tenant string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/api/v1/export", nil)
	c.Set("tenant_id", tenant)
	return c
}

func encryptedCell(t *testing.T, enc *tenantcrypto.Encryptor, tenant, plain string) string {
	t.Helper()
	ct, err := enc.Encrypt(context.Background(), tenant, []byte(plain))
	if err != nil {
		t.Fatalf("暗号化できません: %v", err)
	}
	return "enc:" + base64.StdEncoding.EncodeToString(ct)
}

func exportEncryptorForTest(t *testing.T, tenant string) *tenantcrypto.Encryptor {
	t.Helper()
	ks := tenantcrypto.NewInMemoryKeyStore()
	if _, err := ks.GetKey(context.Background(), tenant); err != nil {
		t.Fatalf("鍵を用意できません: %v", err)
	}
	return tenantcrypto.NewEncryptor(ks)
}

func TestExportDecryptsRawEvent(t *testing.T) {
	const tenant = "t1"
	enc := exportEncryptorForTest(t, tenant)
	h := (&ExportHandler{}).WithEncryptor(enc)

	const plain = `{"cmd":"whoami"}`
	cell := encryptedCell(t, enc, tenant, plain)

	got := h.exportValue(exportTestContext(tenant), cell)

	if got != plain {
		t.Errorf("got %q, want %q", got, plain)
	}
	if strings.HasPrefix(got, "enc:") {
		t.Error("暗号文がそのまま出力に載っています")
	}
}

// 復号できないときに、空欄にしないこと。
// **空欄は「生データが無かった」と同じ姿です。**
func TestExportSaysWhenItCannotDecrypt(t *testing.T) {
	const tenant = "t1"
	cell := "enc:" + base64.StdEncoding.EncodeToString([]byte("not ciphertext"))

	for _, c := range []struct {
		name string
		h    *ExportHandler
	}{
		{"encryptor が付いていない", &ExportHandler{}},
		{"鍵が合わない", (&ExportHandler{}).WithEncryptor(exportEncryptorForTest(t, tenant))},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := c.h.exportValue(exportTestContext(tenant), cell)

			if got == "" {
				t.Error("空欄で出しています。受け取った人には「生データの無い行」と" +
					"区別がつきません")
			}
			if strings.Contains(got, "enc:") {
				t.Errorf("暗号文が出力に載っています: %q", got)
			}
			if !strings.Contains(got, "復号できませんでした") {
				t.Errorf("出せなかったことが書かれていません: %q", got)
			}
		})
	}
}

// 暗号化していないセルには手を触れないこと。
// 平文の列（ホスト名、コマンドライン）まで書き換えると、
// エクスポート全体が壊れます。
func TestExportLeavesPlainCellsAlone(t *testing.T) {
	h := (&ExportHandler{}).WithEncryptor(exportEncryptorForTest(t, "t1"))
	for _, v := range []string{"", "web-01", `{"cmd":"whoami"}`, "encoded", "enc"} {
		if got := h.exportValue(exportTestContext("t1"), v); got != v {
			t.Errorf("平文のセルを書き換えています: %q → %q", v, got)
		}
	}
}

// store 側の判定を通していること。
// エクスポートが独自に前置きを見ていると、片方だけ直したときにずれます。
func TestExportUsesTheSharedPrefixTest(t *testing.T) {
	if !store.IsEncryptedRawEvent("enc:AAAA") {
		t.Error("store.IsEncryptedRawEvent が enc: を暗号文と見ていません")
	}
	if store.IsEncryptedRawEvent("encoded") {
		t.Error("store.IsEncryptedRawEvent が平文を暗号文と見ています")
	}
}
