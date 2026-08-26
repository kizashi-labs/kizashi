package rulepack

import (
	"context"
	"strings"
	"testing"
)

// ★ 実機で踏んだ形をそのまま固定する。
//
// core パックを初めて読ませたとき、DB に同名の未所有ルールが2件あった1ルールで
// UpsertPackRule が失敗した。当時の LoadDir はそこで抜けたので**残り 338 件が
// 丸ごと入らず**、しかも呼び出し側(cmd/api)がそれを致命として扱ったため
// **API が起動できずクラッシュループに入った**。
//
// 正しい振る舞いは3つ同時に成り立つ:
//
//  1. 入れられるルールは入れる（1件の不備で全部を捨てない）
//  2. 入らなかったルールは1件ずつ分かる（件数だけだと運用で追えない）
//  3. それでもエラーは返す（続行することと、失敗を無かったことにすることは別）
func TestLoadDir_ContinuesPastOneBadRule(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "core.json", packJSON("core", "a", "b", "c"))

	up := &fakeUpserter{failOn: "core/b"}
	res, err := LoadDir(context.Background(), up, dir)

	// 1. 残りは入っている
	if res.Rules != 2 {
		t.Errorf("1件の不備で他のルールが落ちています: 取り込めたのは %d 件（2 件のはず）", res.Rules)
	}
	// 2. 落ちたルールが特定できる
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped が %d 件です（1 件のはず）: %+v", len(res.Skipped), res.Skipped)
	}
	if res.Skipped[0].Rule != "b" || res.Skipped[0].Pack != "core" {
		t.Errorf("落ちたルールの特定が違います: %+v", res.Skipped[0])
	}
	if res.Skipped[0].Reason == "" {
		t.Error("理由が空です。運用側は理由を見て重複を解消する")
	}
	// 3. エラーは返る
	if err == nil {
		t.Fatal("取り込めなかったルールがあるのにエラーが返りませんでした")
	}
	if !strings.Contains(err.Error(), "b") {
		t.Errorf("エラーが対象ルールを名指ししていません: %v", err)
	}
}

// 全て成功したときに余計なエラーを返さないこと。ここが壊れると、正常な
// 読み込みのたびに「失敗」が記録され、本当の失敗が埋もれる。
func TestLoadDir_NoErrorWhenAllRulesLand(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "core.json", packJSON("core", "a", "b"))

	res, err := LoadDir(context.Background(), &fakeUpserter{}, dir)
	if err != nil {
		t.Fatalf("全件成功したのにエラーが返りました: %v", err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("Skipped が空ではありません: %+v", res.Skipped)
	}
	if res.Rules != 2 {
		t.Errorf("取り込み件数が違います: %d", res.Rules)
	}
}
