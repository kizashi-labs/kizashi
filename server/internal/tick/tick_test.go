package tick

import (
	"context"
	"errors"
	"testing"
)

// ここは `tick.go` 自身の振る舞いだけを見ます。
//
// **リポジトリ全体を走査する台帳ゲート（未追跡ワーカーの一覧、
// `BackgroundFailed` の分類、Warn / 黙殺の上限）は別 PR です。**
// あちらは本流の木に合わせて較正されており、このエディションでは
// 数も一覧も合いません。較正と、足りていない計測の追加をまとめて
// 独立に扱います。
//
// ただし、それを理由にこの package を**テストゼロで入れる**のは筋が
// 通りません。112 か所がここを呼びます。最低限、この4つは押さえます:
//
//   - `Fail` は回に届く（届いた回は成功として刻まれない）
//   - `Fail` は回の外でも落ちない
//   - 回ごとに記録が独立している
//   - `FailComponent` は部品の件数を残したまま回も落とす

func TestFailReachesTheRun(t *testing.T) {
	var seen int
	Run(context.Background(), "t", func(ctx context.Context) {
		Fail(ctx, errors.New("読み出しが途中で切れました"), "この回は仕事を終えられませんでした")
		if !Failing(ctx) {
			t.Error("Fail を呼んだのに Failing が false です")
		}
		seen = Failures(ctx)
	})
	if seen != 1 {
		t.Errorf("この回の記録が %d 件です（1 のはず）", seen)
	}
}

func TestFailOutsideARunIsQuietButDoesNotPanic(t *testing.T) {
	// 起動時に一度だけ走る初期化など、回の外から呼ばれる経路がある。
	// 記録先が無いだけで、落ちてはいけない。
	Fail(context.Background(), errors.New("x"), "回の外です")

	if Failing(context.Background()) {
		t.Error("回の外なのに Failing が true です")
	}
	if n := Failures(context.Background()); n != 0 {
		t.Errorf("回の外の Failures が %d です（0 のはず）", n)
	}
}

func TestRunGivesEachRunItsOwnRecord(t *testing.T) {
	// 1 回目だけ失敗させ、2 回目に持ち越さないことを見る。
	// 持ち越すと「一度失敗したワーカーは永久に失敗中」になる。
	Run(context.Background(), "t", func(ctx context.Context) {
		Fail(ctx, errors.New("一度目だけ失敗"), "一度目")
	})

	Run(context.Background(), "t", func(ctx context.Context) {
		if Failing(ctx) {
			t.Error("前の回の記録が持ち越されています")
		}
		if n := Failures(ctx); n != 0 {
			t.Errorf("新しい回の記録が %d 件です（0 のはず）", n)
		}
	})
}

func TestFailComponentMarksTheRunAsWellAsTheComponent(t *testing.T) {
	// **これがこの package の主眼です。** `BackgroundFailed` だけを呼ぶと
	// 部品の件数は増えるのに、その回は成功として刻まれる。両方する。
	Run(context.Background(), "t", func(ctx context.Context) {
		FailComponent(ctx, "tick_test_component",
			errors.New("読み出しが途中で切れました"),
			"この回は仕事を終えられませんでした")
		if !Failing(ctx) {
			t.Error("FailComponent を呼んだのに、この回が成功のままです")
		}
		if n := Failures(ctx); n != 1 {
			t.Errorf("この回の記録が %d 件です（1 のはず）", n)
		}
	})
}

func TestWithStateGivesFailSomewhereToLand(t *testing.T) {
	// Run を通さずに Fail の届き先を用意する経路。検査で使う。
	ctx := WithState(context.Background())
	Fail(ctx, errors.New("y"), "検査用")
	if n := Failures(ctx); n != 1 {
		t.Errorf("WithState の記録が %d 件です（1 のはず）", n)
	}
}
