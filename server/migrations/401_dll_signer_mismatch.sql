-- 337: 署名者ミスマッチによる DLL サイドローディング検知(未活用の signer テレメトリ)。
--
-- 2026-07-20 の深掘り続き。image_load イベントは signer(署名サブジェクト、Sysmon EID7
-- Signature に相当)を出しエイリアス層で Signer/Signature として公開済みなのに、自ルールが
-- 未使用だった。migration 336(unsigned のシステム DLL 名)を相補し、本ルールは
-- 「有効署名だが発行者が Microsoft 以外」＝攻撃者が自前/窃取証明書で署名した偽システム
-- DLL(SignatureStatus=valid で unsigned フィルタを回避する手口)を捕捉する。
-- category: image_load。冪等: ON CONFLICT DO NOTHING。

INSERT INTO rules (id, name, type, platform, severity, content, enabled, auto_isolate, auto_kill, mitre_tags, created_at)
VALUES (
  'f1a0c0de-0337-0001-0001-000000000001',
  'System DLL Name Signed by Non-Microsoft Publisher',
  'sigma',
  ARRAY['windows'],
  7,
  $SIGMA$title: System DLL Name Signed by Non-Microsoft Publisher
id: f1a0c0de-0337-0001-0001-000000000001
status: stable
description: Detects a validly signed module bearing the name of a core Windows system DLL but signed by a publisher other than Microsoft and loaded from outside the system directories which indicates a re-signed fake system DLL used to bypass unsigned-DLL detection during side-loading
references:
  - https://attack.mitre.org/techniques/T1574/001/
  - https://attack.mitre.org/techniques/T1036/
logsource:
  product: windows
  category: image_load
detection:
  hijack_dll:
    ImageLoaded|endswith:
      - \version.dll
      - \wininet.dll
      - \secur32.dll
      - \userenv.dll
      - \cryptsp.dll
      - \profapi.dll
      - \dbgcore.dll
      - \dbghelp.dll
      - \edputil.dll
      - \netutils.dll
      - \wtsapi32.dll
  valid_signed:
    SignatureStatus: valid
  filter_ms_publisher:
    Signature|contains:
      - Microsoft
      - Windows
  filter_system:
    ImageLoaded|contains:
      - \Windows\System32\
      - \Windows\SysWOW64\
      - \Windows\WinSxS\
      - \Windows\servicing\
  condition: hijack_dll and valid_signed and not filter_ms_publisher and not filter_system
falsepositives:
  - A third-party product that ships its own signed DLL sharing one of these core system DLL names
level: high$SIGMA$,
  true,
  false,
  false,
  ARRAY['T1574.001', 'T1036'],
  NOW()
) ON CONFLICT (id) DO NOTHING;
