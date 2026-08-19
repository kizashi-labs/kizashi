-- 336: DLL 検索順ハイジャック検知の拡充(未活用の image_load 署名テレメトリ)。
--
-- 2026-07-20 の深掘り続き。image_load イベントは ImageLoaded/SignatureStatus を
-- 出しており、既存 builtin "Untrusted DLL Loaded From User-Writable Path" は
-- 「user-writable パスの unsigned DLL」を汎用カバー済み。本ルールは相補的に、
-- 「よく悪用されるシステム DLL 名」が System32/SysWOW64/WinSxS の外で unsigned に
-- ロードされる古典的な検索順ハイジャック(T1574.001)を捕捉する。DLL 名を絞るため
-- Program Files アプリ配下(既存ルールの user-path 対象外)でも低FPで検知できる。
-- category: image_load。冪等: ON CONFLICT DO NOTHING。

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0336-0001-0001-000000000001',
  'DLL Search-Order Hijack of Commonly-Abused System DLL',
  'sigma',
  ARRAY['windows'],
  8,
  $SIGMA$title: DLL Search-Order Hijack of Commonly-Abused System DLL
id: f1a0c0de-0336-0001-0001-000000000001
status: stable
description: Detects an unsigned or invalidly-signed copy of a frequently hijacked system DLL loaded from outside the standard system directories which is the classic DLL search-order hijacking and side-loading technique
references:
  - https://attack.mitre.org/techniques/T1574/001/
  - https://attack.mitre.org/techniques/T1574/002/
logsource:
  product: windows
  category: image_load
detection:
  hijack_dll:
    ImageLoaded|endswith:
      - \version.dll
      - \dbghelp.dll
      - \dbgcore.dll
      - \wininet.dll
      - \cryptsp.dll
      - \profapi.dll
      - \dwmapi.dll
      - \edputil.dll
      - \msimg32.dll
      - \secur32.dll
      - \userenv.dll
      - \netutils.dll
      - \winmm.dll
      - \textshaping.dll
      - \vftrace.dll
      - \wtsapi32.dll
  untrusted:
    SignatureStatus|contains:
      - unsigned
      - invalid
      - expired
  filter_system:
    ImageLoaded|contains:
      - \Windows\System32\
      - \Windows\SysWOW64\
      - \Windows\WinSxS\
      - \Windows\servicing\
  condition: hijack_dll and untrusted and not filter_system
falsepositives:
  - In-house or niche software shipping an unsigned copy of one of these DLL names in its own directory
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1574.001', 'T1574.002'],
  NOW()
) ON CONFLICT (id) DO NOTHING;
