package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	tenantcrypto "github.com/edr-platform/server/internal/crypto"
)

// 暗号化を有効にする前に、読み出し側が両方読めること。
//
// 平文と暗号文は混在します。移行はしないので、`enc:` の有無で1行ずつ
// 判断します。**この検査は書き込み側を有効にする前に要ります。**
// 順番を逆にすると、書けるが読めないデータが増えます。
//
// 以前の読み出し側は `enc:` が付いていたら代入しませんでした。暗号化を
// 有効にした瞬間から、アナリストの画面は生イベントの無いアラートで
// 埋まります —— 復号できないことと、生イベントが無いことが同じ姿に
// なるわけです。このブランチがずっと追ってきた形です。

func encryptorForTest(t *testing.T, tenant string) *tenantcrypto.Encryptor {
	t.Helper()
	ks := tenantcrypto.NewInMemoryKeyStore()
	// GetKey は鍵が無ければ作ります。
	if _, err := ks.GetKey(context.Background(), tenant); err != nil {
		t.Fatalf("鍵を用意できません: %v", err)
	}
	return tenantcrypto.NewEncryptor(ks)
}

func TestPlaintextRawEventStillReads(t *testing.T) {
	s := &AlertStore{}
	stored := `{"cmd":"whoami"}`
	got, err := s.decodeRawEvent(context.Background(), "t1", &stored)
	if err != nil {
		t.Fatalf("平文を読めません: %v", err)
	}
	if string(got) != stored {
		t.Errorf("got %s, want %s", got, stored)
	}
}

func TestEncryptedRawEventIsDecrypted(t *testing.T) {
	const tenant = "t1"
	enc := encryptorForTest(t, tenant)
	s := &AlertStore{encryptor: enc}

	plain := `{"cmd":"whoami"}`
	ct, err := enc.Encrypt(context.Background(), tenant, []byte(plain))
	if err != nil {
		t.Fatalf("暗号化できません: %v", err)
	}
	stored := encryptedRawEventPrefix + base64.StdEncoding.EncodeToString(ct)

	got, err := s.decodeRawEvent(context.Background(), tenant, &stored)
	if err != nil {
		t.Fatalf("復号できません: %v", err)
	}
	if string(got) != plain {
		t.Errorf("got %s, want %s", got, plain)
	}
	if !json.Valid(got) {
		t.Error("復号結果が JSON ではありません")
	}
}

// 復号できないときに、生イベントが無いことにしないこと。
// **黙って空を返すのが、直そうとしている形そのものです。**
func TestUndecryptableRawEventIsAnError(t *testing.T) {
	stored := encryptedRawEventPrefix + base64.StdEncoding.EncodeToString([]byte("not ciphertext"))
	for _, c := range []struct {
		name   string
		store  *AlertStore
		tenant string
	}{
		{"encryptor が無い", &AlertStore{}, "t1"},
		{"テナントが分からない", &AlertStore{encryptor: encryptorForTest(t, "t1")}, ""},
		{"鍵が合わない", &AlertStore{encryptor: encryptorForTest(t, "t1")}, "t1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.store.decodeRawEvent(context.Background(), c.tenant, &stored)
			if err == nil {
				t.Error("復号できなかったのに成功を返しています。" +
					"呼び出し側は「生イベントが無いアラート」として扱います")
			}
			if got != nil {
				t.Errorf("失敗したのに値を返しています: %s", got)
			}
		})
	}
}

func ptrToEmpty() *string { e := ""; return &e }

func TestEmptyRawEventIsNotAnError(t *testing.T) {
	s := &AlertStore{}
	for _, stored := range []*string{nil, ptrToEmpty()} {
		got, err := s.decodeRawEvent(context.Background(), "t1", stored)
		if err != nil {
			t.Errorf("空を失敗として返しています: %v", err)
		}
		if got != nil {
			t.Errorf("got %s, want nil", got)
		}
	}
}

// 書き込み側と読み出し側が、同じ前置きを使っていること。
// 片方だけ変えると、書いたものが読めなくなります。
func TestWriteAndReadAgreeOnThePrefix(t *testing.T) {
	const tenant = "t1"
	enc := encryptorForTest(t, tenant)
	s := &AlertStore{encryptor: enc}

	a := &StoredAlert{ID: "a1", TenantID: tenant, RawEvent: json.RawMessage(`{"x":1}`)}
	stored, err := s.prepareRawEvent(context.Background(), a)
	if err != nil {
		t.Fatalf("prepareRawEvent: %v", err)
	}
	if stored == nil || !strings.HasPrefix(*stored, encryptedRawEventPrefix) {
		t.Fatalf("暗号化されていません: %v", stored)
	}
	got, err := s.decodeRawEvent(context.Background(), tenant, stored)
	if err != nil {
		t.Fatalf("書いたものを読めません: %v", err)
	}
	if string(got) != `{"x":1}` {
		t.Errorf("got %s, want {\"x\":1}", got)
	}
}
