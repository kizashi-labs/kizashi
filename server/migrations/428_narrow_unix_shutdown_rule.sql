-- 428: 通常の再起動では鳴らないようにする（T1529 / Unix）
--
-- migration 386 で入れた `Unix System Shutdown or Reboot` の条件を狭める。
-- 旧条件は
--
--     sel_bin or sel_systemctl or sel_init
--
-- で、**あらゆる shutdown / reboot / poweroff / halt** が発火した。
--
-- ── なぜ直すか ──
--
-- FP ソークで dev-machine と macbook に計 6 件（3599.98 件/1000ホスト/日）出ていた。
-- 鳴っていたのは
--
--     shutdown -r now
--     shutdown -r +5 / -r +1
--
-- で、OS 更新後の再起動そのものである。**マシンを再起動することは攻撃ではない。**
--
-- ── 判断の根拠は同技法の Windows 側にある ──
--
-- T1529 のルールは 3 本あり（技法で横断検索し、存在しない技法での対照付きで確認）、
-- **Windows 側は既に「強制」を要求している**:
--
--   Forced System Shutdown or Reboot            migration 385   sel_shutdown and sel_forced
--                                                               （sel_forced = ' /f' / ' /t 0' / ' -t 0'）
--   Forced System Shutdown or Reboot via shutdown.exe  builtin  ← 本 PR で同様に是正
--   Unix System Shutdown or Reboot              migration 386   ← 本 migration
--
-- つまり「T1529 で見るべきなのは*強制・即時の*停止である」という判断は、この
-- リポジトリに既にある。Unix 側だけがその概念を持っていなかった。
--
-- 破壊的マルウェアやワイパーは、後片付け（サービス停止・ジャーナルの flush・sync）を
-- 飛ばすために強制フラグを使う。管理者は逆にそれを避ける。そこが分かれ目である。
--
--   -f / --force     シャットダウンスクリプトを飛ばす
--   -n / --no-sync   sync() を飛ばす（＝データ損失を厭わない）
--   --no-wall        ログイン中のユーザへの警告を出さない
--
-- ── ATT&CK スコアカードへの影響は無い ──
--
-- T1529 の固定ケース（attack_coverage_test.go:134,138）はいずれも Windows の
-- `shutdown /r /f /t 0` で、`/f` と `/t 0` を含むため強制を要求しても緑のままである。
-- Unix のケースは固定されていない。
--
-- ── sel_init は据え置く ──
--
-- `init 0` / `init 6` も通常の再起動手段だが、**ソークのプロファイルに現れないため
-- 誤検知の実測が無い**。測っていないものを推測で狭めるのは、この一連の作業で避けて
-- きた行為なので手を付けない。将来プロファイルが `init` を実行するようになったら
-- 再検討する。

UPDATE rules
SET content = $$title: Unix System Shutdown or Reboot
id: f1a0c0de-0328-0002-0002-000000000002
status: stable
description: Detects forced or sync-skipping system shutdown/reboot on Unix hosts — the variants that bypass the clean shutdown sequence, used by wipers and destructive tooling to finalise damage. An ordinary reboot (shutdown -r now) is routine maintenance and is deliberately NOT matched; the signal is the forcing flag, mirroring the Windows rules for this technique.
references:
  - https://attack.mitre.org/techniques/T1529/
logsource:
  product: linux
  category: process_creation
detection:
  sel_bin:
    Image|endswith:
      - /shutdown
      - /reboot
      - /poweroff
      - /halt
  sel_systemctl:
    Image|endswith: /systemctl
    CommandLine|contains:
      - reboot
      - poweroff
      - halt
  forced:
    CommandLine|contains:
      - ' -f'
      - ' --force'
      - ' -n'
      - ' --no-sync'
      - ' --no-wall'
  sel_init:
    Image|endswith:
      - /init
      - /telinit
    CommandLine|contains:
      - ' 0'
      - ' 6'
  condition: ((sel_bin or sel_systemctl) and forced) or sel_init
falsepositives:
  - An administrator force-rebooting an unresponsive host
level: low$$,
    updated_at = now()
WHERE name = 'Unix System Shutdown or Reboot';
