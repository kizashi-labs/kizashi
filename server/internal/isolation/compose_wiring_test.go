package isolation

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestComposePassesExemptToEveryIsolatingService guards the wiring, not the code.
//
// 2026-08-20 に見つかった欠陥: docker-compose.yml が api サービスに
// AUTO_ISOLATE_EXEMPT を渡していなかった。cmd/api はこの変数を読んで Gatekeeper に
// 渡すが、渡ってこないので除外リストは常に空。Gatekeeper は len(exempt) > 0 の
// ときだけ除外を見るので、**除外検査そのものがスキップされていた**。
//
// api 経由の隔離経路（AIトリアージ・プレイブック・自動修復・隔離アクション API）は
// 安全弁が一つも無い状態で、detection にだけ設定した運用者は「除外した」と
// 思いながら api 経由なら隔離できてしまう。プラットフォーム自身が動くホストを
// 守るつもりで守れていない。
//
// ★この形はコードを読んでも見つからない。cmd/api のコメントはむしろ
// 「環境変数だけが両方に配られていたので、外形上は効いているように見える」と
// 書いており、実際には配られてすらいなかった。#792 でコードは入り、配線だけが
// 残っていた。だから検査の対象は Go ではなく compose である。
//
// 判定の作りについて: 「隔離しうるサービス」を列挙して固定するのではなく、
// **Go 側が os.Getenv で読んでいるサービスを見つけて、その全部に配線を要求する**。
// 列挙を固定すると、新しくサービスが増えたときに列挙の更新漏れで検査がすり抜ける
// ——それはこの検査が防ごうとしている欠陥と同じ形になる。
func TestComposePassesExemptToEveryIsolatingService(t *testing.T) {
	root := repoRootFromIsolationPkg(t)

	// 1) AUTO_ISOLATE_EXEMPT を読む cmd/* を洗い出す。
	cmds, err := filepath.Glob(filepath.Join(root, "server", "cmd", "*", "main.go"))
	if err != nil || len(cmds) == 0 {
		t.Fatalf("server/cmd/*/main.go が見つかりません: %v", err)
	}
	var readers []string
	for _, c := range cmds {
		b, err := os.ReadFile(c)
		if err != nil {
			t.Fatalf("読み込みに失敗: %s: %v", c, err)
		}
		if strings.Contains(string(b), `os.Getenv("AUTO_ISOLATE_EXEMPT")`) {
			readers = append(readers, filepath.Base(filepath.Dir(c)))
		}
	}
	if len(readers) == 0 {
		t.Fatal("AUTO_ISOLATE_EXEMPT を読む cmd が1つも無い。" +
			"読み出しごと消えたなら、この検査も一緒に見直すこと")
	}

	// 2) compose の各サービスブロックを取り出す。
	compose := mustReadComposeFile(t, filepath.Join(root, "docker-compose.yml"))
	blocks := composeServiceBlocks(compose)

	// 3) cmd 名から compose のサービス名への対応。compose 側は複製された
	//    レプリカ（detection-2）も持つので、前方一致で拾う。
	for _, cmd := range readers {
		var checked int
		for svc, body := range blocks {
			if svc != cmd && !strings.HasPrefix(svc, cmd+"-") {
				continue
			}
			checked++
			// YAML のマージキー（`<<: *anchor`）で他サービスを丸ごと継承している
			// ブロックは、自分の本文に書いていなくても展開後には持っている
			// （detection-2 が detection を継承する形）。ここでテキストだけを
			// 見ると「配線が無い」と誤って報告する。継承元は同じ検査を受けるので、
			// 継承しているブロックは免除してよい。
			if mergeKeyRe.MatchString(body) {
				continue
			}
			if !strings.Contains(body, "AUTO_ISOLATE_EXEMPT:") {
				t.Errorf("compose のサービス %q に AUTO_ISOLATE_EXEMPT がありません。"+
					"cmd/%s はこの変数を読んで Gatekeeper に渡しますが、渡ってこないと "+
					"除外リストが空になり、Gatekeeper は除外検査そのものをスキップします"+
					"（隔離の安全弁が無い状態になります）", svc, cmd)
			}
		}
		if checked == 0 {
			t.Errorf("cmd/%s は AUTO_ISOLATE_EXEMPT を読みますが、対応する compose の"+
				"サービスが見つかりません。サービス名が変わったならこの対応付けを直すこと", cmd)
		}
	}
}

// composeServiceRe はサービス境界（2スペース字下げのキー）。
//
// ★アンカー付きの `  detection: &detection-base` も境界として拾うこと。
// 最初の実装は `:[ \t]*$` で行末を要求したためアンカー行を境界と認識できず、
// **api のブロックが detection の設定まで飲み込んでいた**。その状態で api の
// AUTO_ISOLATE_EXEMPT を消しても、detection の分を見て「ある」と判定し、
// 検査が素通りした（変異検査で発覚）。境界の取りこぼしは、そのまま
// 「隣のサービスの設定で合格する」という空振りになる。
var composeServiceRe = regexp.MustCompile(`(?m)^  ([a-z0-9_-]+):(?:[ \t].*)?$`)

// mergeKeyRe はサービス直下の YAML マージキー（`    <<: *anchor`）。
// environment の中の `      <<: *common-env` とは字下げで区別する——後者は
// 環境変数の一部を継承するだけで、サービス定義そのものの継承ではない。
var mergeKeyRe = regexp.MustCompile(`(?m)^    <<: \*`)

// composeServiceBlocks は「2スペース字下げのキー」をサービス境界として本文を切る。
// トップレベルの services: 以外（volumes: networks:）も拾うが、それらに
// AUTO_ISOLATE_EXEMPT が要求されることは無いので実害が無い。
func composeServiceBlocks(compose string) map[string]string {
	locs := composeServiceRe.FindAllStringSubmatchIndex(compose, -1)
	out := make(map[string]string, len(locs))
	for i, loc := range locs {
		name := compose[loc[2]:loc[3]]
		end := len(compose)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out[name] = compose[loc[0]:end]
	}
	return out
}

func mustReadComposeFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("読み込みに失敗: %s: %v", path, err)
	}
	return string(b)
}

// repoRootFromIsolationPkg は internal/isolation から見たリポジトリルートを返す。
func repoRootFromIsolationPkg(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("作業ディレクトリの取得に失敗: %v", err)
	}
	// .../server/internal/isolation → .../
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "docker-compose.yml")); err != nil {
		t.Skipf("compose ファイルが同梱されていないためスキップします: %v", err)
	}
	return root
}
