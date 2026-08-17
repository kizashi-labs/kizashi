//go:build linux

package collector

// defaultFIMRules returns the default set of FIM rules for Linux.
// These cover critical system files that are common targets for persistence
// and privilege-escalation attacks.
func defaultFIMRules() []FIMRule {
	return []FIMRule{
		// Individual sensitive files
		{Path: "/etc/passwd", Recursive: false},
		{Path: "/etc/shadow", Recursive: false},
		{Path: "/etc/hosts", Recursive: false},
		{Path: "/etc/sudoers", Recursive: false},
		{Path: "/etc/crontab", Recursive: false},
		{Path: "/etc/ssh/sshd_config", Recursive: false},
		// SSH authorized_keys — persistence via backdoored public keys (T1098.004).
		// Cover root AND every regular user's home via a glob so per-user
		// authorized_keys / shell-rc persistence is no longer invisible (the
		// prior list watched only /root, so /home/<user>/.ssh writes were never
		// hashed — confirmed by the 2026-07-06 Linux active measurement).
		{Path: "/root/.ssh", Recursive: false},
		{Path: "/home/*/.ssh", Recursive: false},
		// Shell startup files — persistence via shell configuration (T1546.004).
		{Path: "/root/.bashrc", Recursive: false},
		{Path: "/root/.bash_profile", Recursive: false},
		{Path: "/root/.profile", Recursive: false},
		{Path: "/home/*/.bashrc", Recursive: false},
		{Path: "/home/*/.bash_profile", Recursive: false},
		// **`.bash_login` は監視されていませんでした。** builtin ルール
		// "Linux Shell Init File Modification (FIM)" は description でこの
		// ファイルを名指ししていますが、FIM が一度もハッシュしないので、
		// このファイルに対しては**発火のしようがありません**。ルールの
		// 側だけを見ると被覆済みに見えるのが、この抜けの厄介なところです。
		//
		// bash はログインシェルで `.bash_profile` → `.bash_login` →
		// `.profile` の順に**最初に見つかった1つだけ**を読みます。前2つが
		// 無い環境では `.bash_login` が唯一の実行経路になります。
		{Path: "/home/*/.bash_login", Recursive: false},
		{Path: "/root/.bash_login", Recursive: false},
		{Path: "/home/*/.profile", Recursive: false},
		{Path: "/home/*/.zshrc", Recursive: false},
		{Path: "/etc/profile.d", Recursive: false},
		// Per-user systemd units & XDG autostart — boot/login persistence (T1543.002 / T1547.013).
		{Path: "/home/*/.config/systemd/user", Recursive: true},
		{Path: "/home/*/.config/autostart", Recursive: true},
		// System-level systemd units — root service persistence (T1543.002). The
		// per-user path above misses /etc/systemd/system, where a dropped .service
		// (or a .d/ drop-in override) runs as root at boot; recursive to catch
		// override directories.
		{Path: "/etc/systemd/system", Recursive: true},
		// Cron persistence (T1053.003): per-user crontabs + system drop-in dirs.
		{Path: "/var/spool/cron", Recursive: true},
		{Path: "/etc/cron.d", Recursive: false},
		{Path: "/etc/cron.hourly", Recursive: false},
		{Path: "/etc/cron.daily", Recursive: false},
		{Path: "/etc/cron.weekly", Recursive: false},
		{Path: "/etc/cron.monthly", Recursive: false},
		// Boot/init persistence (T1037.004).
		{Path: "/etc/rc.local", Recursive: false},
		// Dynamic-linker preload hijack — near-zero legitimate presence, a classic
		// userland-rootkit persistence/evasion primitive (T1574.006).
		{Path: "/etc/ld.so.preload", Recursive: false},
		// System binary directories (non-recursive, first level only)
		{
			Path:      "/bin",
			Recursive: false,
			Exclude:   []string{},
		},
		{
			Path:      "/usr/bin",
			Recursive: false,
			Exclude:   []string{},
		},
		{
			Path:      "/sbin",
			Recursive: false,
			Exclude:   []string{},
		},
		{
			Path:      "/usr/sbin",
			Recursive: false,
			Exclude:   []string{},
		},
	}
}
