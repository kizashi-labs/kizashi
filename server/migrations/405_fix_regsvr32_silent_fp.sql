-- 341: Regsvr32 LOLBin ルールのサイレント登録 FP を是正。
--
-- 2026-07-20 の名前衝突/良性コマンド FP 調査で、"Suspicious Regsvr32 Usage for
-- LOLBin Execution"(019, T1218.010)が CommandLine|contains の OR リストに '/s' を
-- 含むため、正規のサイレント COM 登録(インストーラが多用する
-- `regsvr32 /s <Program Files の DLL>`)で high 誤発火することが判明。
-- '/s' は単なる silent フラグで悪性ではない。悪性 LOLBin 指標('/i:'/scrobj.dll/
-- http/.sct = リモートスクリプトレット実行)は残すため実検知は維持。
-- '/s' のリスト項目のみ除去。冪等(既に除去済みなら no-op)。

UPDATE rules
SET content = replace(content, E'\n      - ''/s''', ''),
    updated_at = NOW()
WHERE id = 'a1b2c3d4-0006-0006-0006-000000000029'
  AND content LIKE '%''/s''%';
