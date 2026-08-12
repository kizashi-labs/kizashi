-- 366: DB側 parity ルール 'Ingress Tool Transfer via LOLBin (DB)' の certutil セレクタから
-- ローカル変換オプション(-decode / -encode / -decodehex)を外し、T1140 側を別ルールに分離する。
--
-- これは PR #592 でビルトイン側 (internal/detection/sigma_builtins.go の
-- "CertUtil Used for File Download") に対して行った修正の、**DBテーブル側の写し**である。
-- 片側だけ直していた:
--
--   server-api    (AlertPipeline)  → Go ビルトイン Sigma          … #592 で修正済み
--   server-detect (Engine/RuleEngine) → rules テーブル (本移行)   … バグが残っていた
--
-- CLAUDE.md「検知ルールの二重管理」が警告しているとおり、同じ技法のルールが両方に存在し、
-- 片方を直しても他方は直らない。実際に FP ソークが捕まえた:
-- #592 で it-admin プロファイルに良性の `certutil -decode`(配布物の base64 証明書を
-- ローカル復号)を追加したところ、ビルトイン側は沈黙したが DB 側が 6件発火した。
--
-- 修正内容はビルトイン側と同じ:
--   ・ダウンロード規則は実際にフェッチを起こすオプション(-urlcache / -verifyctl / -split)に限定
--   ・ローカル変換(-decode/-encode/-decodehex)は T1140 の別ルールへ分離し、
--     ダウンロードオプションを伴う場合は除外(連鎖はダウンロード側が担当し二重発火しない)
--   ・"/" 接頭辞も併記(certutil は両方受け付けるため、"-" のみの列挙は回避される)

UPDATE rules SET content = $$title: Ingress Tool Transfer via LOLBin (DB)
description: Detects certutil or bitsadmin abused to download/stage payloads (LOLBin ingress tool transfer). Scoped to the options that actually cause a network fetch; -decode/-encode/-decodehex are purely local transforms and live in the T1140 rule below.
status: stable
level: high
tags:
  - attack.t1105
  - attack.command_and_control
logsource:
  category: process_creation
detection:
  certutil:
    CommandLine|contains|all:
      - "certutil"
    CommandLine|contains:
      - "-urlcache"
      - "-verifyctl"
      - "-split"
      - "/urlcache"
      - "/verifyctl"
      - "/split"
  bitsadmin:
    CommandLine|contains|all:
      - "bitsadmin"
      - "/transfer"
  condition: certutil or bitsadmin
falsepositives:
  - Legitimate certificate management or Windows Update / software distribution
$$
WHERE name = 'Ingress Tool Transfer via LOLBin (DB)';

-- T1140 側。ビルトインの "CertUtil Used for Local Base64 Decode" と対になる。
-- ダウンロードオプションを伴う場合は除外するので、download+decode の連鎖では
-- 上のルールだけが発火する（分析者が「取得」と「復号」を区別できる状態を保つ）。
INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags, description, enabled)
SELECT 'CertUtil Local Encode/Decode (DB)', 'sigma', ARRAY['windows'], 5,
$$title: CertUtil Local Encode/Decode (DB)
description: Detects certutil performing a local encode/decode transform with no download option present. Commonly used to reconstitute a payload staged in text form to evade content inspection.
status: stable
level: medium
tags:
  - attack.t1140
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "certutil"
    CommandLine|contains:
      - "-decode"
      - "-encode"
      - "-decodehex"
      - "/decode"
      - "/encode"
      - "/decodehex"
  download:
    CommandLine|contains:
      - "-urlcache"
      - "-verifyctl"
      - "/urlcache"
      - "/verifyctl"
  condition: selection and not download
falsepositives:
  - Administrators converting certificates between PEM and DER
$$,
'builtin-parity', ARRAY['T1140'],
'Two-engine parity: certutil local decode/encode (T1140), split out of the T1105 ingress rule', true
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE name = 'CertUtil Local Encode/Decode (DB)');

-- ─────────────────────────────────────────────────────────────────────────────
-- 追補 (FPソーク 2026-08-03 の実測を受けて)
--
-- 上の certutil だけを直したのは不十分だった。PR #592 はビルトイン側の LOLBin
-- ルールを **4件** 直しているのに、DB 側パリティは certutil しか写していない。
-- ソークは4件すべての DB ルールが良性トラフィックで発火することを示した:
--
--   CMSTP Proxy Execution (DB)        6件  ← `.inf` (cmstp の必須引数)
--   CertUtil Local Encode/Decode (DB) 6件  ← 良性の証明書変換
--   Odbcconf Proxy Execution (DB)     4件  ← `/a` / `.dll` (全アクション共通の構文)
--   InstallUtil Proxy Execution (DB)  3件  ← `/u` (通常のアンインストール)
--
-- ゲートが落としたのは前2件だけだが、それは残り2件が**ベースラインに既に載って
-- いた**からで、良性である事実は変わらない。「ベースラインにある＝正しい」ではない。
--
-- 弁別子はビルトイン側 (#592) と同一にする:
--   CMSTP       → /s ・ /ns (サイレント導入。プロファイル導入自体は良性)
--   InstallUtil → 出力抑制オプションのみ (/logfile= ・ /logtoconsole=false)
--   Odbcconf    → REGSVR のみ (DLL のプロキシ実行はこれ)

UPDATE rules SET content = $$title: CMSTP Proxy Execution (DB)
description: Detects cmstp.exe installing an INF connection-manager profile SILENTLY (/s or /ns), the form abused to proxy-execute code and bypass application control / UAC. Plain profile installation always carries .inf, so .inf alone does not discriminate.
status: stable
level: high
tags:
  - attack.t1218.003
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  cmstp:
    CommandLine|contains|all:
      - "cmstp"
    CommandLine|contains:
      - "/s"
      - "/ns"
  condition: cmstp
falsepositives:
  - Silent connection-manager deployment by a management system
$$
WHERE name = 'CMSTP Proxy Execution (DB)';

UPDATE rules SET content = $$title: InstallUtil Proxy Execution (DB)
description: Detects InstallUtil invoked with output-suppressing options, the form used to proxy-execute a .NET assembly while hiding its output. A bare /u is an ordinary service uninstall and does not discriminate.
status: stable
level: medium
tags:
  - attack.t1218.004
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  installutil:
    CommandLine|contains|all:
      - "installutil"
    CommandLine|contains:
      - "/logfile="
      - "/logtoconsole=false"
  condition: installutil
falsepositives:
  - Installer tooling that suppresses log output deliberately
$$
WHERE name = 'InstallUtil Proxy Execution (DB)';

UPDATE rules SET content = $$title: Odbcconf Proxy Execution (DB)
description: Detects odbcconf.exe loading a DLL via REGSVR (LOLBin proxy execution). /a and .dll appear in every ordinary CONFIGSYSDSN invocation, so REGSVR is the only discriminating token.
status: stable
level: high
tags:
  - attack.t1218.008
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  odbcconf:
    CommandLine|contains|all:
      - "odbcconf"
    CommandLine|contains:
      - "regsvr"
  condition: odbcconf
falsepositives:
  - Rare legitimate driver registration through REGSVR
$$
WHERE name = 'Odbcconf Proxy Execution (DB)';

-- CertUtil ローカル変換: 良性の証明書フォーマット変換を除外する。
--
-- 「出力が実行可能形式のときだけ鳴らす」案は採らなかった。攻撃側が .dat に出して
-- 後からリネームすれば素通りするうえ、T1140 の要点は「テキストで運んだものを
-- 復元すること」であって、その場の出力拡張子ではない。
-- 代わりに**既知の良性パターンを除外**する: 証明書拡張子 (.cer/.crt/.der/.pfx/.p7b)
-- が現れる変換は証明書のフォーマット変換であって、ペイロード復元ではない。
-- `.b64` は除外に入れない — `payload.b64 → payload.dat` を見逃すため。
UPDATE rules SET content = $$title: CertUtil Local Encode/Decode (DB)
description: Detects certutil performing a local encode/decode transform with no download option present. Commonly used to reconstitute a payload staged in text form to evade content inspection. Certificate-format conversion is excluded.
status: stable
level: medium
tags:
  - attack.t1140
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "certutil"
    CommandLine|contains:
      - "-decode"
      - "-encode"
      - "-decodehex"
      - "/decode"
      - "/encode"
      - "/decodehex"
  download:
    CommandLine|contains:
      - "-urlcache"
      - "-verifyctl"
      - "/urlcache"
      - "/verifyctl"
  certconv:
    CommandLine|contains:
      - ".cer"
      - ".crt"
      - ".der"
      - ".pfx"
      - ".p7b"
  condition: selection and not download and not certconv
falsepositives:
  - Payload staging that deliberately names its output with a certificate extension
$$
WHERE name = 'CertUtil Local Encode/Decode (DB)';
