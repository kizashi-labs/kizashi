//go:build linux

package collector

import "testing"

// TestDefaultFIMRulesCoverShellInitFiles pins the files that the server's
// builtin rule "Linux Shell Init File Modification (FIM)" claims to detect.
//
// **その規則は、FIM が実際に監視しているファイルの一覧を知りません。**
// description に名前が載っているだけで発火するわけではなく、ハッシュされて
// いないファイルへの書き込みはイベントを1件も生みません。片側だけを見ると
// 被覆済みに見えるので、突き合わせをここに固定します。
//
// `.bash_login` は実際に抜けていました（2026-08-17 に補填）。
func TestDefaultFIMRulesCoverShellInitFiles(t *testing.T) {
	watched := make(map[string]bool)
	for _, r := range defaultFIMRules() {
		watched[r.Path] = true
	}

	// server/internal/detection/sigma_builtins.go の
	// "Linux Shell Init File Modification (FIM)" が名指ししているファイル。
	// 片方を足したらもう片方も足すこと。
	for _, p := range []string{
		"/home/*/.bashrc",
		"/home/*/.bash_profile",
		"/home/*/.bash_login",
		"/home/*/.profile",
		"/home/*/.zshrc",
		"/etc/profile.d",
	} {
		if !watched[p] {
			t.Errorf("%s が既定のFIMルールにありません —— "+
				"builtin ルールはこのファイルを名指ししていますが、"+
				"ハッシュされないので書き込んでも発火しません", p)
		}
	}

	// root also has a login shell, and it is the account an attacker wants.
	for _, p := range []string{
		"/root/.bashrc",
		"/root/.bash_profile",
		"/root/.bash_login",
		"/root/.profile",
	} {
		if !watched[p] {
			t.Errorf("%s が既定のFIMルールにありません", p)
		}
	}
}
