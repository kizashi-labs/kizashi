package collector

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/edr-platform/agent/internal/telemetry"
)

// FIM が黙っていることは、画面では「そのファイルは変わっていない」と
// 読まれます。**実際には3つの別々のことが同じ沈黙になっていました:**
//
//	1. 本当に変わっていない
//	2. 読みに行ったが開けなかった（権限・I/O）
//	3. 監視対象そのものを見に行けなかった（stat / walk が失敗）
//
// この端末で測った既定ルールの内訳: **31 本中 14 本が 0 パス**、
// ログは1行も出ません（`/etc/crontab` `/etc/ld.so.preload`
// `/var/spool/cron` など）。無いこと自体は正常です —— 攻撃はそれを
// 「作る」ことで、作られれば created で上がります。**問題は、無いのか
// 見られなかったのかが、外からまったく区別できなかったことです。**

// ── 道具 ────────────────────────────────────────────────────────────────

// withHashFailure makes hashFileFn fail for the given paths.
//
// root で走るので chmod では読めなくなりません。**実環境が必ず成功する
// 条件では、失敗の分岐は一度も通りません。**
func withHashFailure(t *testing.T, fail map[string]bool) {
	t.Helper()
	orig := hashFileFn
	hashFileFn = func(p string) (string, error) {
		if fail[p] {
			return "", os.ErrPermission
		}
		return orig(p)
	}
	t.Cleanup(func() { hashFileFn = orig })
}

// fimEvents returns every fim_change payload seen, in order.
func fimEvents(c *captureSender) []fimChangePayload {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []fimChangePayload
	for _, b := range c.batches {
		for _, e := range b.GetEvents() {
			id := e.GetId()
			if !strings.HasPrefix(id, "fim_change:") {
				continue
			}
			parts := strings.SplitN(id, ":", 3)
			if len(parts) != 3 {
				continue
			}
			var p fimChangePayload
			if json.Unmarshal([]byte(parts[2]), &p) == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

func clearFIMTelemetry(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { telemetry.Forget(fimSensor) })
	telemetry.Forget(fimSensor)
}

func fimTelemetry() (telemetry.SensorState, bool) {
	for _, s := range telemetry.Snapshot() {
		if s.Sensor == fimSensor {
			return s, true
		}
	}
	return telemetry.SensorState{}, false
}

// ── 読めなかったファイル ────────────────────────────────────────────────

// 読めない期間をはさんでも、中身が同じなら「変更」は出ないこと。
//
// **以前は出ていました。** 読めなかった時点で基準値を "" で潰していたので、
// 読めるように戻った瞬間に `"" != h` となって modified が上がります。
// `/etc/shadow` や `authorized_keys` —— いちばん信用されている経路での
// 偽陽性です。触っていないファイルに担当者が呼び出されます。
func TestAnUnreadableSpellDoesNotInventAChange(t *testing.T) {
	clearFIMTelemetry(t)
	root := t.TempDir()
	target := filepath.Join(root, "shadow")
	if err := os.WriteFile(target, []byte("root:!:19000:::::\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sender := &captureSender{}
	f := newTestFIM(sender, []FIMRule{{Path: target}})
	f.seedHashes()

	// 読めない期間。中身は触りません。
	withHashFailure(t, map[string]bool{target: true})
	f.scan(context.Background())
	hashFileFn = hashFile // 権限が戻った
	f.scan(context.Background())

	if got := fimEvents(sender); len(got) != 0 {
		t.Fatalf("触っていないファイルに %d 件のイベントが出ました: %+v。"+
			"**読めなかった期間を「変更」に化けさせています**", len(got), got)
	}
}

// 読めない期間をはさんで本当に変わったときは、**変更前のハッシュが残ること。**
//
// 以前は基準値が "" に潰れていたので、modified は出ても
// `old_hash` が空でした。担当者は「何から何に変わったか」を追えません。
func TestAChangeAcrossAnUnreadableSpellKeepsItsBaseline(t *testing.T) {
	clearFIMTelemetry(t)
	root := t.TempDir()
	target := filepath.Join(root, "authorized_keys")
	if err := os.WriteFile(target, []byte("ssh-rsa AAAA legit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := hashFile(target)
	if err != nil {
		t.Fatal(err)
	}

	sender := &captureSender{}
	f := newTestFIM(sender, []FIMRule{{Path: target}})
	f.seedHashes()

	withHashFailure(t, map[string]bool{target: true})
	f.scan(context.Background())
	hashFileFn = hashFile

	if err := os.WriteFile(target,
		[]byte("ssh-rsa AAAA legit\nssh-rsa BBBB attacker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.scan(context.Background())

	got := fimEvents(sender)
	if len(got) != 1 || got[0].ChangeType != "modified" {
		t.Fatalf("modified が1件出るはずが %+v", got)
	}
	if got[0].OldHash != before {
		t.Errorf("old_hash = %q, want %q。**変更前が分からない変更通知は、"+
			"何が起きたかを追えません**", got[0].OldHash, before)
	}
}

// 読めなかったことが、端末の外に出ること。
//
// **ログ1行では足りません。** agent のローカルログは SOC の画面に
// 出ません。読めないあいだ FIM が返す沈黙は「変更なし」と同じ姿です。
func TestUnreadableFilesAreReportedOffTheEndpoint(t *testing.T) {
	clearFIMTelemetry(t)
	root := t.TempDir()
	target := filepath.Join(root, "shadow")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	withHashFailure(t, map[string]bool{target: true})

	f := newTestFIM(&captureSender{}, []FIMRule{{Path: target}})
	f.seedHashes()

	st, ok := fimTelemetry()
	if !ok {
		t.Fatal("読めないファイルがあるのに、telemetry に何も登録されていません。" +
			"**サーバから見て、この端末は「監視していて変更が無い」端末と同じです**")
	}
	if st.Mode != telemetry.ModeFailed {
		t.Errorf("mode = %q, want %q", st.Mode, telemetry.ModeFailed)
	}
	if st.Reason == "" {
		t.Error("理由が空です。件数が無いと、1件なのか全部なのか分かりません")
	}
}

// 健全なときは、**登録しないこと。**
//
// FIM は設計上ポーリングです。劣化ではありません。ここで常に登録すると
// 全 Linux 端末の集約が倒れ、**本物の劣化がその中に埋もれます。**
func TestAHealthyFIMDoesNotFlipTheFleetView(t *testing.T) {
	clearFIMTelemetry(t)
	root := t.TempDir()
	target := filepath.Join(root, "passwd")
	if err := os.WriteFile(target, []byte("root:x:0:0::/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := newTestFIM(&captureSender{}, []FIMRule{{Path: target}})
	f.seedHashes()
	f.scan(context.Background())

	if st, ok := fimTelemetry(); ok {
		t.Errorf("健全なのに %q として登録されています (%s)", st.Mode, st.Reason)
	}
}

// 読めるように戻ったら、登録も消えること。
//
// **直らない赤は、赤でないのと同じです。** 見る人が無視するようになり、
// 本当に落ちた端末がその中に埋もれます。
func TestARecoveredFIMStopsReportingFailed(t *testing.T) {
	clearFIMTelemetry(t)
	root := t.TempDir()
	target := filepath.Join(root, "shadow")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	withHashFailure(t, map[string]bool{target: true})
	f := newTestFIM(&captureSender{}, []FIMRule{{Path: target}})
	f.seedHashes()
	if _, ok := fimTelemetry(); !ok {
		t.Fatal("読めない時点で登録されていません")
	}

	hashFileFn = hashFile // 権限が戻った
	f.scan(context.Background())

	if st, ok := fimTelemetry(); ok {
		t.Errorf("読めるように戻ったのに %q のままです (%s)", st.Mode, st.Reason)
	}
}

// 存在しないパスは、失敗として数えないこと。
//
// この端末では既定 31 本のうち 14 本が 0 パスです。**そのほとんどは
// 正常です** —— `/etc/ld.so.preload` が無いのが普通で、攻撃はそれを
// 作ることです。ここを失敗に数えると、ほぼ全端末が赤くなり、
// 本当に見えていない端末がその中に埋もれます。
func TestAnAbsentPathIsNotAFailure(t *testing.T) {
	clearFIMTelemetry(t)
	root := t.TempDir()
	missing := filepath.Join(root, "ld.so.preload")

	f := newTestFIM(&captureSender{}, []FIMRule{{Path: missing}})
	f.seedHashes()

	if st, ok := fimTelemetry(); ok {
		t.Errorf("存在しないだけのパスで %q になっています (%s)", st.Mode, st.Reason)
	}
	if len(f.blocked) != 0 {
		t.Errorf("blocked = %v, want 空", f.blocked)
	}
}

// 存在しないパスに、あとから作られたものは created で上がること。
// **上の抑制が、作成の検知まで消していないこと。**
func TestAnAbsentPathStillCatchesCreation(t *testing.T) {
	clearFIMTelemetry(t)
	root := t.TempDir()
	preload := filepath.Join(root, "ld.so.preload")

	sender := &captureSender{}
	f := newTestFIM(sender, []FIMRule{{Path: preload}})
	f.seedHashes()

	if err := os.WriteFile(preload, []byte("/tmp/evil.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.scan(context.Background())

	got := fimEvents(sender)
	if len(got) != 1 || got[0].ChangeType != "created" || got[0].Path != preload {
		t.Fatalf("created が1件出るはずが %+v", got)
	}
}

// ── 見に行けなかった対象 ────────────────────────────────────────────────

// blockedTree builds root/gate/watched/{a,b,c} and returns the rule path.
func blockedTree(t *testing.T, root string) (rulePath, gate string, files []string) {
	t.Helper()
	gate = filepath.Join(root, "gate")
	watched := filepath.Join(gate, "watched")
	if err := os.MkdirAll(watched, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a", "b", "c"} {
		p := filepath.Join(watched, n)
		if err := os.WriteFile(p, []byte("content "+n), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	return watched, gate, files
}

// 見に行けなかった対象の配下を、「削除された」と言わないこと。
//
// **この端末で測った実数: `/usr/bin` は 1065 パスです。** stat が1回
// 失敗すると、以前は 1065 件の削除が上がり、基準値が全部消え、次の
// スキャンで 1065 件の作成が上がりました。**何も起きていません。**
func TestAnUnreachableTargetIsNotAMassDeletion(t *testing.T) {
	clearFIMTelemetry(t)
	root := t.TempDir()
	rulePath, gate, files := blockedTree(t, root)

	sender := &captureSender{}
	f := newTestFIM(sender, []FIMRule{{Path: rulePath, Recursive: true}})
	f.seedHashes()
	if len(f.hashes) != len(files) {
		t.Fatalf("baseline = %d, want %d", len(f.hashes), len(files))
	}

	// gate をディレクトリから通常ファイルに差し替えます。
	// stat(gate/watched) は ENOTDIR —— **「無い」ではなく「見に行けない」です。**
	if err := os.RemoveAll(gate); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gate, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.scan(context.Background())

	if got := fimEvents(sender); len(got) != 0 {
		t.Fatalf("見に行けなかっただけで %d 件のイベントが出ました: %+v", len(got), got)
	}
	if len(f.hashes) != len(files) {
		t.Errorf("基準値が %d 件に減りました (want %d)。**消すと、"+
			"戻ったときに全部が「作成」として上がります**", len(f.hashes), len(files))
	}
	st, ok := fimTelemetry()
	if !ok || st.Mode != telemetry.ModeFailed {
		t.Errorf("見に行けない対象があるのに telemetry = %+v (ok=%v)", st, ok)
	}
}

// 本当に消えたものは、これまで通り「削除」で上がること。
// **上の抑制が、削除の検知まで消していないこと。**
func TestAConfirmedAbsenceIsStillADeletion(t *testing.T) {
	clearFIMTelemetry(t)
	root := t.TempDir()
	rulePath, _, files := blockedTree(t, root)

	sender := &captureSender{}
	f := newTestFIM(sender, []FIMRule{{Path: rulePath, Recursive: true}})
	f.seedHashes()

	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	f.scan(context.Background())

	got := fimEvents(sender)
	if len(got) != 1 || got[0].ChangeType != "deleted" || got[0].Path != files[0] {
		t.Fatalf("deleted が1件出るはずが %+v", got)
	}
	if _, still := f.hashes[files[0]]; still {
		t.Error("削除したパスが基準値に残っています")
	}
}

// 見に行けるように戻ったら、抑制も戻ること。
//
// **`blocked` を持ち越すと、そのあと本当に消されたものが永久に
// 報告されなくなります。** 抑制は今回のスキャンにだけ効きます。
func TestTheSuppressionDoesNotOutliveTheBlock(t *testing.T) {
	clearFIMTelemetry(t)
	root := t.TempDir()
	rulePath, gate, files := blockedTree(t, root)

	sender := &captureSender{}
	f := newTestFIM(sender, []FIMRule{{Path: rulePath, Recursive: true}})
	f.seedHashes()

	if err := os.RemoveAll(gate); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gate, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.scan(context.Background()) // 抑制される

	// 元に戻します。ただし a は戻しません —— 本当に消えました。
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rulePath, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range files[1:] {
		if err := os.WriteFile(p, []byte("content "+filepath.Base(p)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f.scan(context.Background())

	var deleted []string
	for _, e := range fimEvents(sender) {
		if e.ChangeType == "deleted" {
			deleted = append(deleted, e.Path)
		}
	}
	if !reflect.DeepEqual(deleted, []string{files[0]}) {
		t.Fatalf("deleted = %v, want %v。**抑制が次のスキャンまで残ると、"+
			"本当に消されたものが報告されません**", deleted, []string{files[0]})
	}
	if len(f.blocked) != 0 {
		t.Errorf("blocked = %v, want 空", f.blocked)
	}
}

// ── 差し替え口そのもの ──────────────────────────────────────────────────

// 既定の読み取りが本物であること。
//
// **差し替え口を作って既定を留めないと、製品が常に「読めた」を返す
// 実装に置き換わっても検査は緑のままです。** このキャンペーンで
// `readVmRSSFn` のときに同じ穴を開けかけました。
func TestTheDefaultFIMHashReaderIsTheRealOne(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "probe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("kizashi"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	want, err := hashFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	got, err := hashFileFn(f.Name())
	if err != nil || got != want {
		t.Fatalf("hashFileFn = (%q, %v), want (%q, nil)", got, err, want)
	}
	if got == "" {
		t.Fatal("ハッシュが空です")
	}

	// 開けないパスは、エラーで返ること（"" と nil ではないこと）。
	if _, err := hashFileFn(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("存在しないパスが成功として返りました")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want os.ErrNotExist", err)
	}
}

// captureSender が実際に fim_change を拾えていること。
//
// **「イベントが0件」を主張する検査は、拾えていなくても緑になります。**
// 上のいくつかがその形なので、拾える側を1本だけ確かめておきます。
func TestTheCaptureActuallySeesFIMEvents(t *testing.T) {
	sender := &captureSender{}
	f := newTestFIM(sender, nil)
	f.emitEvent(context.Background(), "/etc/probe", "modified", "old", "new")

	got := fimEvents(sender)
	want := []fimChangePayload{{
		Path: "/etc/probe", ChangeType: "modified", OldHash: "old", NewHash: "new",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
