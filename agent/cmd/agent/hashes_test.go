package main

import (
	"testing"

	"github.com/edr-platform/agent/internal/collector"
)

// 計算したハッシュが、イベントに載ること。
//
// **エージェントは起動するプロセスごとに実行ファイルを最大 50 MB 読んで
// MD5・SHA1・SHA256 を計算し、`evt.Hashes` に入れて、proto に載せる
// ところで捨てていました。** proto には `FileHashes hashes = 8` が
// あります。プロセスイベントもファイルイベントも同じでした。
//
// サーバのハッシュ IOC 照合は、**照合するものを一度も受け取って
// いません。** 一致しなかったのではなく、材料が届いていませんでした。
// 端末側では毎回ハッシュを計算していたので、費用だけ払っていました。

func TestComputedHashesReachTheWire(t *testing.T) {
	got := protoHashes(collector.FileHashes{
		MD5: "d41d8", SHA1: "da39a", SHA256: "e3b0c",
	})
	if got == nil {
		t.Fatal("計算したハッシュが落ちています")
	}
	if got.GetMd5() != "d41d8" || got.GetSha1() != "da39a" || got.GetSha256() != "e3b0c" {
		t.Errorf("載せ方がずれています: %+v", got)
	}
}

// 取れなかったハッシュは、欄ごと出さないこと。
//
// **3つとも空の FileHashes を載せると、サーバからは「ハッシュを取ったが
// 空だった」に見えます。** 測っていないことを測定値にしない、という
// 同じ規則です。
func TestUnavailableHashesAreOmitted(t *testing.T) {
	if got := protoHashes(collector.FileHashes{}); got != nil {
		t.Errorf("空のハッシュを載せています: %+v", got)
	}
}

// 一部だけ取れた場合は載せること。**塞ぐ側だけ直して、取れた分まで
// 捨てないこと。**
func TestPartialHashesAreStillReported(t *testing.T) {
	if got := protoHashes(collector.FileHashes{SHA256: "e3b0c"}); got == nil {
		t.Fatal("SHA256 だけ取れた分を捨てています")
	}
}
