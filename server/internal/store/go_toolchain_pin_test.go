package store

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Go のバージョンは 2 か所で決まり、片方だけ動くと CI は緑のまま出荷物が古くなる。
//
//	go.mod の `go` ディレクティブ  → CI が使う（setup-go の go-version-file）
//	Dockerfile の golang: イメージ → 実際に配布されるバイナリを作る
//
// 2026-08-13、標準ライブラリの脆弱性 7 件（GO-2026-6218 ほか）に対して go.mod だけが
// 1.26.6 へ上がり、Dockerfile は 1.26.5 のまま残った。この状態では govulncheck は
// 通るのに、docker build が作るサーバ・エージェントのバイナリは脆弱なままになる。
// **緑になったことが、直っていないことを隠す。**
//
// 直し忘れではなく、そもそも 2 か所ある構造の問題なので、ずれたら落ちるようにする。

var (
	goDirectiveRe   = regexp.MustCompile(`(?m)^go\s+(\d+\.\d+(?:\.\d+)?)\s*$`)
	golangImageRe   = regexp.MustCompile(`golang:(\d+\.\d+(?:\.\d+)?)-`)
	goModsToCompare = []string{"server/go.mod", "agent/go.mod"}
)

// repoRoot returns the repository root relative to this package.
func repoRoot() string { return filepath.Join("..", "..", "..") }

// ゲート自身が、実際に起きたずれを読み取れること。
//
// 一致を報告するテストは、そもそも読めていない場合も同じ結果を出す。
// 2026-08-13 に実在した組み合わせ（go.mod=1.26.6 / Dockerfile=1.26.5）を
// 食わせて、両方の値をきちんと取り出せることを確かめる。
func TestToolchainPinPatternsReadTheRealFormats(t *testing.T) {
	m := goDirectiveRe.FindStringSubmatch("module github.com/edr-platform/server\n\ngo 1.26.6\n\nrequire (\n")
	if m == nil || m[1] != "1.26.6" {
		t.Errorf("go ディレクティブを読み取れない: %v", m)
	}
	// toolchain 行や go 1.26 のような 2 桁表記も落とさない
	if m := goDirectiveRe.FindStringSubmatch("go 1.26\n"); m == nil || m[1] != "1.26" {
		t.Errorf("2 桁の go ディレクティブを読み取れない: %v", m)
	}

	got := golangImageRe.FindAllStringSubmatch(
		"FROM golang:1.26.5-alpine AS builder\nFROM golang:1.26.5-alpine AS agent-builder\n", -1)
	if len(got) != 2 || got[0][1] != "1.26.5" {
		t.Errorf("golang イメージの版を読み取れない: %v", got)
	}
	if got[0][1] == "1.26.6" {
		t.Error("ずれた組み合わせを一致と判定している")
	}
}

func TestDockerfileGoVersionMatchesGoMod(t *testing.T) {
	root := repoRoot()

	// go.mod 側の期待値。server と agent が食い違っていること自体も検出する
	// （片方だけ上げると、同じ脆弱性がもう片方に残る）。
	want := ""
	for _, rel := range goModsToCompare {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		m := goDirectiveRe.FindStringSubmatch(string(b))
		if m == nil {
			t.Fatalf("%s に go ディレクティブが見つからない", rel)
		}
		if want == "" {
			want = m[1]
			continue
		}
		if m[1] != want {
			t.Errorf("%s の go ディレクティブが %s、他は %s。"+
				"片方だけ上げると同じ脆弱性がもう片方に残る", rel, m[1], want)
		}
	}

	// Dockerfile 側。golang: を FROM しているものを全部見る。
	var checked int
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 権限等で読めないものは飛ばす（走査全体を落とさない）
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.Contains(strings.ToLower(d.Name()), "dockerfile") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for _, m := range golangImageRe.FindAllStringSubmatch(string(b), -1) {
			checked++
			if m[1] != want {
				t.Errorf("%s が golang:%s を FROM しているが、go.mod は %s。\n"+
					"CI は go.mod を見るので緑になるが、docker build が作る"+
					"バイナリは古い標準ライブラリのまま出荷される", rel, m[1], want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if checked < 3 {
		t.Fatalf("golang: イメージの参照が %d 件しか見つからない（3 件以上あるはず）。"+
			"走査が壊れていると、ずれていても「一致」に見える", checked)
	}
}
