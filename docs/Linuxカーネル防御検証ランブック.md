# Linux カーネル防御 検証ランブック（eBPF LSM / Ph0 PoC）

**対象**: [Linux改ざん防止と実行前防御設計.md](design/Linux改ざん防止と実行前防御設計.md) の Ph0（実行前防御 PoC）。
**目的**: `lsm=bpf` を有効化した使い捨て Linux VM 上で、eBPF LSM の `bprm_check_security` フックが execve をブロックできることを実機実証する。
**検証環境方針（付録A-4）**: 常設しない。検証のたびに VM をスポット起動 → 実証 → 破棄する。

> ✅ **実機検証済み（2026-06-19, RHEL 10.1 / kernel 6.12.0 / EC2）**: 本手順で eBPF LSM が verifier を通過・attach し、enforce モードで `/tmp/blockme` の execve を `-EPERM`（`Operation not permitted`, exit 126）で拒否、audit モードでは記録のみで許可することを確認。観測専用 tracepoint にできない実行前防御が eBPF LSM で動作することを実証した。なお production agent には未配線（Ph2+ で配線）。

---

## 1. 前提カーネルの確認

対象は **kernel 5.13+**（enforce 下限、付録A-1）。RHEL 10.1 / Ubuntu 22.04+ が候補。

```bash
uname -r                                   # 5.13 以上か
zgrep CONFIG_BPF_LSM /boot/config-$(uname -r)   # =y であること
cat /sys/kernel/security/lsm               # 現在有効な LSM 一覧
ls /sys/kernel/btf/vmlinux                 # BTF 存在（CO-RE 必須）
```

`/sys/kernel/security/lsm` の出力に **`bpf` が含まれていれば §2 は不要**。含まれない場合のみ §2 を実施。

---

## 2. `lsm=bpf` の有効化（再起動が必要 / ディストロによっては不要）

> ✅ **実機知見**: RHEL 10.1 は標準の LSM 一覧に `bpf` を最初から含む（`lockdown,capability,yama,selinux,bpf,landlock,ima,evm`）。**この場合 §2 は丸ごと不要**。§1 の `cat /sys/kernel/security/lsm` に `bpf` があればこの節をスキップする。

> 下記は `bpf` が含まれない場合のみ。これがコンテナ/マネージド K8s で prevention を使えない理由（§6 の縮退設計の根拠）。VM では GRUB を編集して再起動する。

`/etc/default/grub` の `GRUB_CMDLINE_LINUX` に **既存の LSM を保ったまま** `bpf` を追加する。現在値を §1 の `lsm=` で確認し、末尾に `,bpf` を足す。

```bash
# 例: 現在 lsm=lockdown,capability,...,bpf が無い場合
sudo sed -i 's/\(GRUB_CMDLINE_LINUX="[^"]*\)"/\1 lsm=lockdown,capability,yama,apparmor,bpf"/' /etc/default/grub
# RHEL 系:
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
# Ubuntu 系:
sudo update-grub
sudo reboot
```

再起動後、再度 `cat /sys/kernel/security/lsm` に `bpf` が含まれることを確認。

---

## 3. ビルドホストの準備

`bpf2go` は clang でカーネル内 BPF を生成する。RHEL 10.1 での実績手順（既存 eBPF と同じ。`libbpf-devel` は CRB リポジトリ）:

```bash
# RHEL/Fedora 系
sudo dnf install -y clang llvm bpftool libbpf-devel golang
# Debian/Ubuntu 系
sudo apt-get install -y clang llvm linux-tools-$(uname -r) libbpf-dev golang
```

> ✅ **実機知見**: 既存 eBPF 検証に使った RHEL 10.1 EC2 では clang/llvm/bpftool/libbpf-devel/golang が**全て導入済**だった（`dnf` は "Nothing to do"）。`subscription-manager` 未登録の警告は無害。

ソースの取得（EC2 は git 無し・PRIVATE リポジトリのため PAT で取得、[[project_tech_debt_ledger]] の ETW 検証と同経路）。**検証対象のブランチ**（未マージなら `main` でなくそのブランチ名）を指定すること。`unzip` は RHEL に無いことが多いので **tarball + tar**（tar は標準導入）を使う:

```bash
read -s PAT          # 画面に出さず PAT を入力（平文で貼らない！）
curl -fsSL -H "Authorization: Bearer $PAT" \
  https://api.github.com/repos/<owner>/edr-platform/tarball/<branch> -o repo.tar.gz
mkdir -p src && tar xzf repo.tar.gz -C src
cd src/*/agent       # 展開先（1階層下）/agent = go.mod のある場所
pwd && ls go.mod
```

> ⚠️ PAT は1回取得すれば不要。検証後は GitHub Settings → PAT で **Revoke** すること。`read -s` を使えば履歴・画面に残らない。

---

## 4. eBPF 生成 + ビルド

RHEL の go は `GOTOOLCHAIN=local` 固定で、go.mod が要求する版より古いと止まる（実機で `go.mod requires go >= 1.26.4 (running 1.26.3)` を踏んだ）。**先に `GOTOOLCHAIN=auto` を設定**して必要版を自動取得させる（ネットワーク制限で取得不可なら、使い捨て展開物の `go.mod` の go directive を手元の版に下げる: `sed -i 's/^go 1\.26\.4$/go 1.26.3/' go.mod && sed -i '/^toolchain /d' go.mod`）。

```bash
export GOTOOLCHAIN=auto      # go.mod 要求版を自動取得（必須）

# CO-RE 用 vmlinux.h（既に agent/ebpf/ にあればスキップ可）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

# ★ bpf2go は「カレントディレクトリ」に生成物を出す。必ず linux パッケージの
#   中で実行すること（agent/ から実行すると生成物が agent/ 直下に落ち、
#   internal/platform/linux のローダから見えず `undefined: PreventionLSMObjects`
#   になる ← 実機で踏んだ罠）。
cd internal/platform/linux
GOPACKAGE=linux go run github.com/cilium/ebpf/cmd/bpf2go \
  -tags "ebpf prevention" -cc clang \
  -cflags "-O2 -g -target bpf -D__TARGET_ARCH_x86" \
  PreventionLSM ../../../ebpf/prevention_lsm.bpf.c
ls -1 preventionlsm_bpf*     # preventionlsm_bpf{el,eb}.go/.o が「ここ」に出ればOK
cd ../../..

# PoC コマンドをビルド
go build -tags "ebpf prevention" -o /tmp/prevention-poc ./cmd/prevention-poc
echo "build rc=$?"
```

> 生成物が誤って `agent/` 直下に出てしまったら `rm -f preventionlsm_bpf*.go preventionlsm_bpf*.o` で掃除してから上記をやり直す。
> `go generate ./internal/platform/linux/...` でも同じ（`prevention_lsm.go` の `//go:generate` 行がパッケージ内で上記を呼ぶ）。こちらはディレクトリ移動が不要。

---

## 5. 実証

ブロック対象は害のない安全なバイナリ（例 `/usr/bin/whoami` をコピーした使い捨て）にすること。**システム必須バイナリ（/bin/bash 等）を enforce でブロックしないこと**（ログインできなくなる恐れ）。

```bash
cp /usr/bin/whoami /tmp/blockme && chmod +x /tmp/blockme
```

SSH 1セッションでも検証できるよう、PoC を `timeout` 付きでバックグラウンド起動し、その窓の中で対象を叩く（別シェルがあれば前面実行でも可）。

### 5-1. audit モード（許可しつつ記録）

```bash
sudo timeout 6 /tmp/prevention-poc -block /tmp/blockme > /tmp/poc-audit.log 2>&1 &
sleep 2
/tmp/blockme; echo "exit=$?"        # 実行は成功する（audit は許可）→ exit=0
wait
cat /tmp/poc-audit.log
```

期待: `/tmp/blockme` が成功（`exit=0`）、ログに `[block] pid=<n> uid=<n> /tmp/blockme -> allowed (audit)`。

### 5-2. enforce モード（実際に拒否）

```bash
sudo timeout 6 /tmp/prevention-poc -block /tmp/blockme -enforce > /tmp/poc-enforce.log 2>&1 &
sleep 2
/tmp/blockme; echo "exit=$?"        # 拒否される → "Operation not permitted", exit=126
wait
cat /tmp/poc-enforce.log
```

期待: `/tmp/blockme: Operation not permitted`、`exit=126`、ログに `[block] ... -> DENIED`。

**`/tmp/blockme` の exec が EPERM で弾かれれば Ph0 成功**＝tracepoint（観測のみ）にはできない「実行前ブロック」が eBPF LSM で実現できることの実機実証。

> ✅ **2026-06-19 に上記のとおり実機で確認済み**（audit: exit=0 / enforce: `Operation not permitted` exit=126）。`timeout` の SIGTERM で `stopped.` とクリーン終了し、LSM プログラムは自動デタッチされる（pin していないため）。

---

## 6. トラブルシュート

| 症状 | 原因/対処 |
|---|---|
| `attach lsm/bprm_check_security ...` で失敗 | `lsm=bpf` 未設定。§1/§2 を再確認（`cat /sys/kernel/security/lsm` に bpf が必要） |
| `load eBPF LSM objects ...` で失敗 | `CONFIG_BPF_LSM=y` でない、または BTF 無し。カーネル要件を満たす VM を使う |
| verifier reject（ロード時エラー） | カーネルが古い/ヘルパ非対応。5.13+ で再試行。エラー全文を控えて `.bpf.c` を見直す |
| 生成物が無くビルド失敗（`PreventionLSMObjects` undefined） | §4 の bpf2go 生成を未実施。clang ホストで実行する |
| enforce にしてもブロックされない | パス完全一致のため、シンボリックリンク経由や相対パスでは別パスになる。`-block` に実体の絶対パスを渡す |
| Go モジュールキャッシュのファイルロックで build 失敗 | 再実行（または `GOMODCACHE=/tmp/gomodcache`）。既存 ETW 検証と同じ既知事象 |

---

## 7. 後始末

```bash
# enforce を残したまま VM を放置しない（誤ブロックの元）
# PoC は Ctrl-C で停止すれば LSM プログラムは自動デタッチされる（pin していない）
rm -f /tmp/blockme /tmp/prevention-poc
```

検証完了後は **VM ごと破棄**（付録A-4：常設しない）。

---

## 8. 生成物の扱い（Ph6 への申し送り）

- Ph0 では生成物（`preventionlsm_bpf*.go/.o`）を**コミットしない**（PoC のため）。
- Ph2 以降で prevention を出荷ビルドに載せる際、既存 eBPF と同様に **生成物をコミットして clang 無しビルドを可能化**する（[[project_tech_debt_ledger]] P4-2 の bpf2go 生成物コミット運用と合流）。これが設計書 Ph6 の中身。

---

## 9. Ph1〜Ph5 実機検証手順（2026-06-19, RHEL 10.1 / kernel 6.12 / EC2 で全 PASS）

§4 で `-tags "ebpf prevention"` ビルド（PreventionLSM＋TamperLSM を生成）した前提。各フェーズは **使い捨て検証物**（agent モジュール内に作り、リポジトリには入れない）で確認する。検証後は VM/`/tmp`/取得ソースを破棄。

> ⚠️ **環境ハマり所（実機で踏んだもの）**: ①agent EC2 と server は別ホスト（例 ip-10-0-0-10 / ip-10-0-0-10）。②`read -s` は一括ペーストで hang → **単独実行**。③`sudo -i` 後は `$API` 等の環境変数が引き継がれない。④root が作った `/tmp/*` は ec2-user で上書き不可 → `sudo rm -f` 先行。⑤後始末でソース/バイナリを消すので**都度 tarball 再取得＋生成物再生成**。

### 9-1. Ph1 保護能力検出（config 不要）

```bash
mkdir -p cmd/detectcheck
cat > cmd/detectcheck/main.go <<'EOF'
package main
import ("fmt"; "github.com/edr-platform/agent/internal/protection")
func main() { fmt.Println(protection.Detect().String()) }
EOF
go run ./cmd/detectcheck
```
期待: `mode=enforce kernel="6.12.0..." btf=true bpf_lsm=true — eBPF LSM usable: ...`

### 9-2. Ph2 prevention audit（完全 E2E、server ルール経由）

1. **server ホスト**で deny ルール投入（admin API が 401/ロック時は DB 直 INSERT で回避）:
```bash
docker exec kizashi-postgres psql -U edr -d edrplatform -c \
"INSERT INTO process_block_rules (name,process_name,rule_type,scope,action,enabled,severity)
 VALUES ('e2e-audit','/tmp/blockme','deny','all','alert',true,'high');"
```
2. **agent EC2**でビルドした `-tags "ebpf prevention"` agent を起動（`/etc/edr-agent/config.toml` を自動使用）。本番サービスは一時停止:
```bash
cp /usr/bin/whoami /tmp/blockme && chmod +x /tmp/blockme
sudo systemctl stop edr-agent
sudo /tmp/edr-agent-prev > /tmp/prev.log 2>&1 &
sleep 10; /tmp/blockme; echo "exit=$?"   # audit=exit0(許可)
sleep 2; sudo pkill -f /tmp/edr-agent-prev; sudo systemctl start edr-agent
grep prevention /tmp/prev.log
```
期待: `[prevention] 実行前防御判定 path=/tmp/blockme rule=e2e-audit verdict=実行を許可（audit/fail-open）`、`exit=0`。

### 9-3. Ph3 prevention enforce（同一ルールでスイッチ ON/OFF 対比）

server に `action=block` ルール（process_name=絶対パス）を用意。`EDR_PREVENTION_ENFORCE=1` の有無で対比:
```bash
# enforce: sudo env EDR_PREVENTION_ENFORCE=1 /tmp/edr-agent-prev ... → /tmp/blockme は Operation not permitted (exit126)
# 既定(env無し):                              /tmp/edr-agent-prev ... → exit0（fail-open）
```
期待: enforce で `verdict=実行を拒否（enforce, -EPERM）` exit≠0、既定で `verdict=実行を許可` exit0。

### 9-4. Ph4/Ph5 tamper（dummy PID を保護して kill 試行）

`cmd/tampercheck`（`-enforce` フラグ＋SIGUSR1 で disarm）を作りビルド（`-tags "ebpf prevention"`）。dummy を保護:
```bash
sleep 600 & DUMMY=$!
# Ph4 audit:   sudo /tmp/tampercheck $DUMMY        → kill $DUMMY 成功(exit0)、log enforced=false
# Ph5 enforce: sudo /tmp/tampercheck -enforce $DUMMY → kill $DUMMY 拒否(Operation not permitted)
#              sudo pkill -USR1 -f tampercheck       → disarm → kill $DUMMY 成功(exit0)
```
期待ログ: `tamper decision: target=<dummy> sender=<pid>(bash) sig=15 enforced=<true/false>`。enforce で拒否、SIGUSR1 後に許可。

### 9-5. 検証で踏んだ修正

- **Ph3 verifier 拒否**（`R0 unknown scalar`）→ §「実装上の教訓」のとおり定数 return 2分岐に修正（PR #230）。LSM bpf 改修時は各 exit を定数 return にすること。

---

## 10. credaccess（認証情報/メモリアクセス検知 T1003/T1055）実機検証（2026-07-02, Ubuntu 6.8 / EC2, [PR#372](https://github.com/kizashi-labs/kizashi/pull/372)）

`lsm/ptrace_access_check` を audit-only で使い、他プロセスのメモリ読取を `credential_access`
イベント化する（設計は[設計書 §4.5](design/Linux改ざん防止と実行前防御設計.md)）。tamper/prevention と
**同じ `lsm=bpf` 要件**。この検証EC2（203.0.113.10）は既定で bpf 不在だったため §2 の手順で有効化した。

```bash
# 1) lsm=bpf 有効化（§2）: /sys/kernel/security/lsm に bpf が無いことを確認 → GRUB 追記 → 再起動
cat /sys/kernel/security/lsm          # 例: lockdown,capability,landlock,yama,apparmor（bpf 無し）
sudoedit /etc/default/grub            # GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,bpf"
sudo update-grub && sudo reboot
# ★再起動で /tmp がクリアされる → agent バイナリ等は再配置が必要
cat /sys/kernel/security/lsm          # 再起動後: …,apparmor,bpf（bpf 追加を確認）

# 2) agent（-tags "ebpf prevention"）起動後、起動ログを確認
grep credaccess /tmp/kizashi-agent.log   # "[credaccess] …起動しました"（= attach 成功。発火保証ではない）

# 3) ★発火の実証（「起動しました」だけでは不十分）: フックが実際に呼ばれるか run_cnt で確認
sudo sysctl -w kernel.bpf_stats_enabled=1
setsid sleep 300 & TPID=$!; sudo timeout 3 strace -p $TPID -e trace=none -o /dev/null
sudo bpftool prog show name check_ptrace   # run_cnt > 0 なら発火（bpf 不在だと run_cnt が付かない=0回）
sudo sysctl -w kernel.bpf_stats_enabled=0

# 4) エンドツーエンド: strace attach → server DB に credential_access が保存されるか
#    （migration294 で events_event_type_check に credential_access 追加済み。未適用だと 23514 で破棄）
sudo docker exec kizashi-postgres psql -U edr -d edrplatform \
  -c "SELECT count(*) FROM events WHERE event_type='credential_access';"
```

期待: `check_ptrace` の run_cnt>0、`credential_access` が events に保存、非 allowlist トレーサ
（strace/gdb/pgrep 等）は `[CRED]` アラート化、良性システムトレーサ（systemd-journal/runc/landscape）は
allowlist で抑制（設計 §4.5）。

### 10-1. 検証で踏んだ罠
- **`bpf_lsm=false` でも attach は成功する**: 「起動しました」ログ＝attach 成功であり発火保証ではない。
  active LSM リストに bpf が無いとフックは呼ばれない（run_cnt=0）。**必ず run_cnt か実イベントで発火確認**。
- **再起動で `/tmp` がクリア**: agent/scorer/スクリプト等の `/tmp` 配置物は再配置が必要。docker は
  `unless-stopped` で自動復帰。
- **`credential_access` 保存ギャップ**: `events_event_type_check` 制約に未収載で全プラットフォーム破棄
  → migration294 で追加（#269/#271 と同型）。
- **detection 側 FP 氾濫**: 既存ハンドラが Windows LSASS 前提で良性 Linux ptrace に Severity-8 偽アラートを
  氾濫 → engine.go で Linux 分岐 + 良性トレーサ allowlist（[PR#372](https://github.com/kizashi-labs/kizashi/pull/372)）。
- **`docker cp` はソースの mode を保持**: 非実行権限のまま cp するとコンテナ起動が permission denied →
  ホスト側で `chmod +x` してから cp。**psql の ARRAY 直書きは SSH heredoc のネスト引用符で壊れる** →
  migration は `.sql` を scp して `psql -f` で適用。

---

## 関連

- 設計: [Linux改ざん防止と実行前防御設計.md](design/Linux改ざん防止と実行前防御設計.md)（Ph6 配布設計＝付録B）
- 技術的負債台帳: [技術的負債と改善計画.md](技術的負債と改善計画.md)（P4-4）
- 既存 ETW 実機検証の同型手順: [ETW検証ランブック.md](ETW検証ランブック.md)
