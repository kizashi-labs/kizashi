-- 340: mimikatz 名前一致 FP の是正(セキュリティ製品名の誤検知)。
--
-- 2026-07-20 の新規ルール adversarial FP 調査で、"MimikatzDetector.exe" のような
-- 防御側ツール名が Image|contains: mimikatz / OriginalFileName|contains: mimikatz に
-- 部分一致して critical 誤発火することが判明。3箇所(builtin=ソース修正済/019/332)の
-- 名前選択を「正確な実行ファイル名の endswith」へ締める。コマンドライン選択
-- (sekurlsa:: 等)は残るため実 mimikatz 実行の検知は維持。冪等: 全文置換。
--   - a1b2c3d4-...006  Mimikatz Credential Dumping (019, Image|contains→endswith)
--   - f1a0c0de-0332-...001  Renamed Offensive Tool (332, OriginalFileName|contains→endswith+variant)

-- (1) 019 Mimikatz: Image|contains: mimikatz → endswith 正確名。
UPDATE rules
SET content = $SIGMA$title: Mimikatz Credential Dumping
id: a1b2c3d4-0002-0002-0002-000000000006
status: stable
description: Detects Mimikatz credential dumping tool execution via common command-line arguments
references:
  - https://attack.mitre.org/techniques/T1003/001/
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith:
      - '\mimikatz.exe'
      - '\mimikatz64.exe'
  selection_cmdline:
    CommandLine|contains:
      - 'sekurlsa::'
      - 'lsadump::'
      - 'kerberos::'
      - 'crypto::'
      - 'privilege::debug'
  condition: selection_image or selection_cmdline
falsepositives:
  - Penetration testing or authorized red team engagements
level: critical$SIGMA$,
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0002-0002-0002-000000000006';

-- (2) 332 Renamed Offensive Tool: OriginalFileName|contains → endswith(正確名)+ variant。
UPDATE rules
SET content = $SIGMA$title: Renamed Offensive Tool by PE OriginalFileName
id: f1a0c0de-0332-0001-0001-000000000001
status: stable
description: Detects offensive security tools by their embedded PE OriginalFileName even when the file on disk has been renamed to evade name-based detection
references:
  - https://attack.mitre.org/techniques/T1036/005/
logsource:
  product: windows
  category: process_creation
detection:
  exact_tool:
    OriginalFileName|endswith:
      - mimikatz.exe
      - rubeus.exe
      - sharphound.exe
      - lazagne.exe
      - seatbelt.exe
      - safetykatz.exe
      - nanodump.exe
      - sharpview.exe
      - certify.exe
      - whisker.exe
      - sharpkatz.exe
  variant_tool:
    OriginalFileName|contains:
      - winpeas
      - koadic
  condition: exact_tool or variant_tool
falsepositives:
  - Security researchers or red teams running the original tools intentionally
  - Defensive tooling whose name merely contains a tool token (endswith on exact PE names avoids this)
level: critical$SIGMA$,
    updated_at = NOW()
WHERE id = 'f1a0c0de-0332-0001-0001-000000000001';
