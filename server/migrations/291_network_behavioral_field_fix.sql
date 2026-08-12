-- 291: ネットワーク系 behavioral ルール3件の壊れたフィールド参照を修正。
--
-- ★サイレント故障(発火履歴 0 で実証): これらは field/distinct_field/group_by に
-- camelCase の dstPort/dstIp/srcIp を使っていたが、検知エンジンの flat map
-- (EventEnvelope.FlatMap + addPipelineSigmaAliases)が持つのは proto の snake_case
-- (dst_port/dst_ip/src_ip)と Sigma エイリアス(DestinationPort/DestinationIp/
-- SourceIp)であり、dstPort/dstIp/srcIp というキーは存在しない
-- → SequenceEngine が該当フィールドを見つけられず 3ルールとも永久に inert。
-- (auth eventName と同型。実測: RDP/ポートスキャン/内部偵察 いずれも ever_fired=0)
-- flat に実在する snake_case 名へ修正して発火可能にする。

-- (1) RDPブルートフォース検知
UPDATE rules SET content = $$
# 30秒以内に同一送信元IPから 8 件以上のRDP(3389)失敗接続。
window: 30s
threshold: 8
event_type: network
field: dst_port
value: 3389
group_by: src_ip
$$, updated_at = NOW()
WHERE name = 'RDPブルートフォース検知';

-- (2) ポートスキャン検知
UPDATE rules SET content = $$
# 10秒以内に同一送信元IPから 15 個以上の異なる宛先ポートへの接続。
window: 10s
threshold: 15
event_type: network
distinct: true
distinct_field: dst_port
group_by: src_ip
$$, updated_at = NOW()
WHERE name = 'ポートスキャン検知';

-- (3) 内部ネットワーク偵察（横展開）
UPDATE rules SET content = $$
# 30秒以内に同一エージェントから 20 個以上の異なる宛先IPへの接続。
window: 30s
threshold: 20
event_type: network
distinct: true
distinct_field: dst_ip
group_by: agent_id
$$, updated_at = NOW()
WHERE name = '内部ネットワーク偵察（横展開）';
