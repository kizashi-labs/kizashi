-- デフォルト検知ルールの投入

-- ─── Sigma Rules ──────────────────────────────────────────────

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, auto_kill, description) VALUES

-- PowerShell エンコードコマンド
('疑わしいPowerShell実行', 'sigma', ARRAY['windows'], 7,
$$
title: 疑わしいPowerShell実行
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - ' -enc '
      - 'DownloadString'
      - 'DownloadFile'
      - '-ExecutionPolicy Bypass'
  condition: selection
$$,
'community', ARRAY['T1059.001'], false, false,
'PowerShellのエンコードされたコマンド実行やダウンロード実行パターンを検知'),

-- ランサムウェア: シャドウコピー削除
('シャドウコピー削除コマンド（ランサムウェア）', 'sigma', ARRAY['windows'], 9,
$$
title: シャドウコピー削除
detection:
  selection:
    CommandLine|contains:
      - 'vssadmin delete shadows'
      - 'wmic shadowcopy delete'
      - 'bcdedit /set {default} recoveryenabled no'
  condition: selection
$$,
'community', ARRAY['T1490'], true, false,
'ランサムウェアがバックアップを削除する前の典型的なコマンドを検知。自動隔離を実行。'),

-- LSASS メモリダンプ
('LSASSメモリダンプ（資格情報窃取）', 'sigma', ARRAY['windows'], 9,
$$
title: LSASS ダンプ
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x147a'
      - '0x1fffff'
  condition: selection
$$,
'community', ARRAY['T1003.001'], true, false,
'MimikatzなどのツールによるLSASSへのアクセスを検知。'),

-- Pass the Hash
('Pass-the-Hash攻撃の検知', 'sigma', ARRAY['windows'], 8,
$$
title: Pass-the-Hash
detection:
  selection:
    EventID: 4624
    LogonType: 3
    LogonProcessName: NtLmSsp
    WorkstationName: '-'
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
$$,
'community', ARRAY['T1550.002'], false, false,
'NTLMハッシュを使ったラテラルムーブメントを検知。'),

-- Linux: 危険なcurlパイプ実行
('curlパイプシェル実行（Linux）', 'sigma', ARRAY['linux'], 6,
$$
title: Curl Pipe Shell
detection:
  selection:
    CommandLine|contains:
      - 'curl|bash'
      - 'curl | bash'
      - 'curl|sh'
      - 'wget|bash'
      - 'wget | bash'
  condition: selection
$$,
'community', ARRAY['T1059.004'], false, false,
'curlで取得したスクリプトを直接実行する危険なパターンを検知。'),

-- macOS: LaunchDaemon追加
('LaunchDaemon永続化（macOS）', 'sigma', ARRAY['darwin'], 7,
$$
title: LaunchDaemon Persistence
detection:
  selection:
    TargetFilename|startswith:
      - '/Library/LaunchDaemons/'
      - '/Library/LaunchAgents/'
    EventType: 'create'
  filter:
    Image|startswith: '/Applications/'
  condition: selection and not filter
$$,
'community', ARRAY['T1543.004'], false, false,
'非正規パスからのLaunchDaemon/LaunchAgent登録を検知。');

-- ─── YARA Rules ───────────────────────────────────────────────

INSERT INTO rules (name, type, platform, severity, content, source, mitre_tags,
                   auto_isolate, description) VALUES

('ランサムウェア身代金ノート', 'yara', ARRAY['windows', 'linux', 'darwin'], 10,
$$
rule RansomNote {
    strings:
        $n1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $n2 = "All your files are encrypted" nocase
        $n3 = "HOW_TO_DECRYPT" nocase
        $btc = /[13][a-km-zA-HJ-NP-Z0-9]{25,34}/
    condition:
        (any of ($n1, $n2, $n3)) and $btc
}
$$,
'community', ARRAY['T1486'], true,
'ランサムウェアの身代金要求ファイルを検知。即座に自動隔離。'),

('Webshell検知', 'yara', ARRAY['linux', 'windows'], 8,
$$
rule Webshell_Common {
    strings:
        $php1 = "<?php" nocase
        $cmd1 = "exec(" nocase
        $cmd2 = "shell_exec(" nocase
        $cmd3 = "passthru(" nocase
        $cmd4 = "system(" nocase
        $b64  = "base64_decode" nocase
        $eval = "eval(" nocase
    condition:
        $php1 and (2 of ($cmd1, $cmd2, $cmd3, $cmd4)) and ($b64 or $eval)
}
$$,
'community', ARRAY['T1505.003'], false,
'PHPウェブシェルの特徴的なパターンを検知。');
