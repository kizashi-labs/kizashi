-- 343: 実行時ダイナミックリンカ注入の検知（T1574.006 / T1574.007）
--
-- 未活用テレメトリの活用: Linux agent は /proc/<pid>/environ から LD_PRELOAD=,
-- LD_LIBRARY_PATH=, LD_AUDIT=, GCONV_PATH= を収集し（readProcSuspiciousEnv,
-- suspiciousEnvPrefixes）、ingestion が `environment`（空白結合形）として正規化・
-- field-support ゲート登録済み（SupportedSigmaFields に "environment"）。だが従来
-- これを使う検知ルールが皆無で、既存の T1574.006 は /etc/ld.so.preload への「ファイル
-- 書き込み」(migration 311) のみ。実際の攻撃で多いのは `LD_PRELOAD=/tmp/x.so ./bin`
-- の「プロセス実行時注入」で、これは file_event に現れずコマンドラインにも残らない
-- （env 経由）。本 migration は environment フィールドでこの死角を埋める。
--
-- FP 対策: 正規の preload ライブラリは /usr/lib・/lib・/usr/local/lib・/opt に置かれる。
-- 世界書き込み可能/ユーザ書き込み可能なパス（/tmp・/dev/shm・/var/tmp・/run/user・
-- /home・memfd）を指す LD_PRELOAD/LD_AUDIT のみを高確度シグナルとして拾う。

-- ── T1574.006 : LD_PRELOAD / LD_AUDIT 実行時注入（疑わしいパス） ──────────
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux Dynamic Linker Injection via LD_PRELOAD/LD_AUDIT (Runtime)', 'sigma', ARRAY['linux'], 8,
$SIGMA$
title: Linux Dynamic Linker Injection via LD_PRELOAD/LD_AUDIT (Runtime)
description: Detects a process started with LD_PRELOAD or LD_AUDIT pointing at a world- or user-writable path (/tmp, /dev/shm, /var/tmp, /run/user, /home, memfd). This forces an attacker-controlled shared object into the process at load time — a userland code-injection / persistence / defense-evasion primitive (T1574.006). Observed via the collected process environment, so it fires even though the injection leaves no trace on the command line and does not touch /etc/ld.so.preload.
status: stable
level: high
tags:
  - attack.t1574.006
  - attack.persistence
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection_var:
    environment|contains:
      - 'LD_PRELOAD='
      - 'LD_AUDIT='
  selection_path:
    environment|contains:
      - '/tmp/'
      - '/dev/shm/'
      - '/var/tmp/'
      - '/run/user/'
      - '/home/'
      - 'memfd:'
  condition: selection_var and selection_path
falsepositives:
  - Rare LD_PRELOAD debugging/profiling frameworks that stage their library under a temp path (review the injected object)
$SIGMA$,
'community', ARRAY['T1574.006'],
'Untapped telemetry (environment): runtime dynamic-linker preload injection, complements the ld.so.preload FIM rule', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux Dynamic Linker Injection via LD_PRELOAD/LD_AUDIT (Runtime)');

-- ── T1574.007 : GCONV_PATH iconv モジュール・ハイジャック ───────────────
-- GCONV_PATH は iconv の変換モジュール検索先を上書きする。正規運用ではほぼ設定
-- されないため、非標準パスを指す GCONV_PATH の存在自体が強いシグナル。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'Linux GCONV_PATH iconv Module Hijack', 'sigma', ARRAY['linux'], 7,
$SIGMA$
title: Linux GCONV_PATH iconv Module Hijack
description: Detects a process started with GCONV_PATH set to a writable/non-standard location. GCONV_PATH overrides where glibc's iconv loads charset-conversion modules from; pointing it at an attacker-controlled directory loads a malicious gconv module (code execution / privilege escalation, T1574.007-style path-interception abuse of the loader). GCONV_PATH is essentially never set in normal operation.
status: experimental
level: high
tags:
  - attack.t1574.006
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    environment|contains: 'GCONV_PATH='
  filter_std:
    environment|contains:
      - 'GCONV_PATH=/usr/lib'
      - 'GCONV_PATH=/lib'
  condition: selection and not filter_std
falsepositives:
  - Bespoke locale/charset toolchains that legitimately set GCONV_PATH (rare; review the target directory)
$SIGMA$,
'community', ARRAY['T1574.006'],
'Untapped telemetry (environment): GCONV_PATH iconv module hijack via the loader', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'Linux GCONV_PATH iconv Module Hijack');
