package rules

import "testing"

// value_any の項目が「コマンド名」ではなく「コマンドラインの句」だったとき、
// 以前は EXACT basename 比較に落ちるため **どんな入力でも一致しなかった**。
// basename に空白は入りえないので、これは書き方の問題ではなく、ルールが
// ロードされ enabled と表示され、しかし発火しえない状態だった。
//
// migration 445 (Linux 復旧阻害) がこの形を使う最初のルールで、修正前は
// 何も検知していなかった。ここが赤くなったら、その状態に戻っている。
func TestValueAnyPhrasesMatchBySubstring(t *testing.T) {
	sr := &sequenceRule{
		field: "commandline",
		valueAny: parseValueAny(
			"btrfs subvolume delete, zfs destroy, rm -rf /var/backups, wipefs -a"),
	}

	for _, cl := range []string{
		"sudo btrfs subvolume delete /.snapshots/42/snapshot",
		"/sbin/zfs destroy tank/backups@daily",
		"sh -c rm -rf /var/backups",
		"wipefs -a /dev/sdb1",
	} {
		if !valueMatches(sr, cl) {
			t.Errorf("句が一致しない: %q", cl)
		}
	}

	for _, cl := range []string{
		"btrfs subvolume list /",         // 破壊操作ではない
		"zfs list -t snapshot",           // 同上
		"cp -pP /sbin/wipefs /var/tmp/x", // パス名の言及だけ（実測された誤検知の形）
	} {
		if valueMatches(sr, cl) {
			t.Errorf("一致してはいけない: %q", cl)
		}
	}
}

// 空白を含まない項目は従来どおり EXACT basename 比較のままであること。
// ここを部分一致に変えると "ss" が "sshd" に当たる（コメントに明記された退行）。
func TestValueAnyBareNamesStayExact(t *testing.T) {
	sr := &sequenceRule{field: "processname", valueAny: parseValueAny("ss, id, tasklist")}

	for _, v := range []string{"ss", "/usr/bin/ss", `C:\Windows\System32\tasklist.exe`} {
		if !valueMatches(sr, v) {
			t.Errorf("コマンド名が一致しない: %q", v)
		}
	}
	for _, v := range []string{"sshd", "/usr/sbin/sshd", "idle"} {
		if valueMatches(sr, v) {
			t.Errorf("部分一致してしまっている: %q", v)
		}
	}
}

// 拡張子トークン（"." 始まり）の部分一致は従来どおり。
func TestValueAnyExtensionTokensStillSubstring(t *testing.T) {
	sr := &sequenceRule{field: "path", valueAny: parseValueAny(".locked, .encrypted")}
	if !valueMatches(sr, "/home/u/report.docx.locked") {
		t.Error("拡張子トークンが一致しない")
	}
	if valueMatches(sr, "/home/u/report.docx") {
		t.Error("無関係なパスに一致している")
	}
}
