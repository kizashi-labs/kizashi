package store

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

// 生イベントを出せなかったことが、応答に載ること。
//
// 直前の形は slog.Error を1行書いてから `return a, nil` でした。運用者が
// ログを見に行けば分かりますが、**アナリストの画面では「生イベントの無い
// アラート」と1ピクセルも違いません。** 鍵の設定を間違えたまま何週間も
// 気づかない、という形です。
//
// answered_with_a_value_test.go の return 系統がこれを数えていて、
// 上限0を超えました。上限を上げるか理由を書くかではなく、応答の側を
// 直しました。

func TestUnreadableRawEventSaysSoInTheResponse(t *testing.T) {
	s := &AlertStore{}
	raw, note := s.rawEventOrNote(context.Background(), "a1", "t1", nil,
		errors.New("connection reset"))

	if raw != nil {
		t.Errorf("読めなかったのに生イベントを返しています: %s", raw)
	}
	if note == nil {
		t.Fatal("読めなかったことが応答に載っていません。" +
			"画面では「生イベントの無いアラート」と区別がつきません")
	}
	if *note != "生イベントを読み出せませんでした" {
		t.Errorf("note = %q", *note)
	}
}

func TestUndecryptableRawEventSaysSoInTheResponse(t *testing.T) {
	// encryptor が無いのに `enc:` が付いている ——
	// TENANT_MASTER_KEY を外したまま再起動した状態です。
	stored := encryptedRawEventPrefix + base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	s := &AlertStore{}

	raw, note := s.rawEventOrNote(context.Background(), "a1", "t1", &stored, nil)

	if raw != nil {
		t.Errorf("復号できていないのに値を返しています: %s", raw)
	}
	if note == nil {
		t.Fatal("復号できなかったことが応答に載っていません")
	}
	if *note != "生イベントを復号できませんでした" {
		t.Errorf("note = %q", *note)
	}
}

// 読めたときは、注記を付けないこと。
// 常に注記が付くなら、付いていること自体が何も言わなくなります。
func TestReadableRawEventCarriesNoNote(t *testing.T) {
	stored := `{"cmd":"whoami"}`
	s := &AlertStore{}

	raw, note := s.rawEventOrNote(context.Background(), "a1", "t1", &stored, nil)

	if note != nil {
		t.Errorf("読めているのに注記が付いています: %s", *note)
	}
	if string(raw) != stored {
		t.Errorf("raw = %s, want %s", raw, stored)
	}
}

// 生イベントが元から無い行に、注記を付けないこと。
// 「無い」と「出せなかった」を取り違えると、今度は逆向きの嘘になります。
func TestAbsentRawEventIsNotAFailure(t *testing.T) {
	s := &AlertStore{}
	for _, stored := range []*string{nil, ptrToEmpty()} {
		raw, note := s.rawEventOrNote(context.Background(), "a1", "t1", stored, nil)
		if note != nil {
			t.Errorf("生イベントが無いだけなのに、出せなかったことにしています: %s", *note)
		}
		if raw != nil {
			t.Errorf("raw = %s, want nil", raw)
		}
	}
}
