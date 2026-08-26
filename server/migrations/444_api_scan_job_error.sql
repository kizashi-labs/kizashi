-- api_scan_jobs にスキャンが失敗した理由を残す列を足します。
--
-- これまで status に 'failed' が入ったことは一度もありません。到達できな
-- かったスキャンは status='completed', endpoints_found=0, vulns_found=0 と
-- して記録されていて、走らせた人には「調べたが脆弱性は無かった」と読めま
-- した。理由の置き場所が無いと、失敗を記録しても「なぜ」が消えます。

ALTER TABLE api_scan_jobs ADD COLUMN IF NOT EXISTS error TEXT;
