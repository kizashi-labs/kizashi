-- 371: 'Binary Falsely Claiming Microsoft Authorship from User-Writable Path'
--      (migration 345) の誤検知を、Microsoft 自身のインストール先を除外して抑える。
--
-- ── なぜ必要か ────────────────────────────────────────────────────────────
-- 345 の前提は「正規の Microsoft 署名バイナリは System32 / Program Files に置かれる」
-- だったが、これは事実に反する。Microsoft 製品の相当数がユーザ書き込み可能な
-- ルート配下の自社サブツリーに常駐する:
--
--   C:\Users\<user>\AppData\Local\Microsoft\Teams\current\Teams.exe
--   C:\Users\<user>\AppData\Local\Microsoft\OneDrive\OneDrive.exe
--   C:\ProgramData\Microsoft\Windows Defender\Platform\<ver>\MsMpEng.exe
--
-- FP ソーク (2026-08-04, PR #543) でこのルールは単独で
-- +20,999.86 /1000ホスト/日 (35件) を出し、ゲート超過 +90,598 の 23.2% を占める
-- 最大の寄与源だった。上記3プロセスがそのまま該当する。
--
-- ── 何を変えるか ──────────────────────────────────────────────────────────
-- drop_path は縮めない。代わりに「書き込み可能ルート直下の \Microsoft\ サブツリー」
-- だけを除外する。Temp / Downloads / Users\Public / Windows\Temp / $Recycle.Bin から
-- 起動する Microsoft 詐称バイナリは従来どおり検知される — そこが本来の高シグナル。
--
-- ── 残るリスク（意図的に受け入れる） ──────────────────────────────────────
-- 攻撃者が %LOCALAPPDATA%\Microsoft\ 配下にペイロードを置けば回避できる。ただし
-- (a) このルールの前提自体がその範囲では成立しない（正規物が同居する場所である）、
-- (b) ProgramData\Microsoft\ 配下は通常 ACL で保護される、
-- (c) 誤検知でルールが黙殺されれば検知率は 0 になる — 誤検知は「うるさい」だけでなく
--     実効検知率を下げる。
-- ディレクトリ単独ではなく署名の有効性で判定するのが本筋だが、process_creation
-- イベントは現状 signature_status を運んでいない（image_load のみ）。それが入るまでの
-- 暫定措置であり、入った時点でこの除外は署名検証に置き換えること。

UPDATE rules
SET content = $SIGMA$
title: Binary Falsely Claiming Microsoft Authorship from User-Writable Path
description: Detects a process whose PE CompanyName claims Microsoft while it runs from a user- or world-writable directory (Temp, AppData, Downloads, Public, ProgramData, Windows\Temp). Genuine Microsoft binaries execute from System32 / Program Files, OR from their own vendor subtree under a writable root (Teams, OneDrive, Defender platform) — the latter is excluded here. A Microsoft-claiming binary launched from a bare drop location is a masquerading implant (T1036.005). Requires CompanyName to be present, so absent version-info never false-fires.
status: experimental
level: high
tags:
  - attack.t1036.005
  - attack.defense_evasion
logsource:
  category: process_creation
detection:
  claims_ms:
    Company|contains: 'Microsoft'
  drop_path:
    Image|contains:
      - '\AppData\Local\Temp\'
      - '\AppData\Roaming\'
      - '\Downloads\'
      - '\Users\Public\'
      - '\ProgramData\'
      - '\Windows\Temp\'
      - '\$Recycle.Bin\'
  vendor_install:
    Image|contains:
      - '\AppData\Local\Microsoft\'
      - '\AppData\Roaming\Microsoft\'
      - '\ProgramData\Microsoft\'
  condition: claims_ms and drop_path and not vendor_install
falsepositives:
  - Rare Microsoft-authored installers that stage a helper under Temp (review the signer/hash)
  - Third-party software that installs under a \Microsoft\ subtree it does not own (would be excluded here)
$SIGMA$,
    description = 'Untapped telemetry (Company): Microsoft-claiming binary from a drop path (Microsoft 自身のインストール先は除外)'
WHERE name = 'Binary Falsely Claiming Microsoft Authorship from User-Writable Path';
