-- 331: alerts.anomaly_score を 0–1 の契約に揃える(既存行の是正)。
--
-- 背景(検証EC2 2026-07-31 で実測): alerts.anomaly_score には 2 つの書き手が
-- あり、スケールが食い違っていた。
--   * detection/engine.go enrichAnomalyScore — UEBA リスク(0–100)を /100 して
--     入れる。= 0–1 (正しい)
--   * detection/anomaly.go — 生の z スコアをそのまま入れていた。z は低分散
--     ベースラインで数百に発散する。
-- UI は `score * 100` を「%」として描画するため、`/endpoints` の
-- 「UEBA 振る舞い異常スコア」が 60786% / 6879% と表示されていた。
--
-- コード側は anomaly.go の normalizeZScore() で是正済み(z を [3,10] → (0,1] に
-- 写像)。この migration は既に保存されてしまった行を同じ写像で揃える。
--
-- 生の z スコアは alerts.description の本文と anomaly_scores テーブルに残るため、
-- ここで丸めても情報は失われない。
--
-- 冪等: 0–1 に収まっている行は WHERE 句で除外されるため、再実行しても
-- 二重に変換されない。

UPDATE alerts
SET anomaly_score = LEAST((anomaly_score - 3.0) / 7.0, 1.0)
WHERE anomaly_score > 1.0;

-- 閾値(z<=3)以下が保存されていた場合は 0 に寄せる。
-- (現行の検知器は z>3 でしか発報しないため通常は該当なし)
UPDATE alerts
SET anomaly_score = 0
WHERE anomaly_score < 0;
