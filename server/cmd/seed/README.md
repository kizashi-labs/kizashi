# edr-seed — デモデータシーダー

Kizashi のデモ・テスト用データを生成します。

## 使用方法

```bash
# フル デモデータ (50エージェント・200アラート・15インシデント・500 IOC)
DATABASE_URL=postgres://... go run ./cmd/seed/ --scenario=full

# ランサムウェア攻撃シナリオ (LockBit 3.0 TTP)
DATABASE_URL=postgres://... go run ./cmd/seed/ --scenario=ransomware

# APT攻撃シナリオ (APT29 TTP)
DATABASE_URL=postgres://... go run ./cmd/seed/ --scenario=apt

# 内部脅威シナリオ (UEBA + 異常行動)
DATABASE_URL=postgres://... go run ./cmd/seed/ --scenario=insider

# 最小データ (5エージェント・10アラート)
DATABASE_URL=postgres://... go run ./cmd/seed/ --scenario=minimal

# デモデータをクリアしてから再シード
DATABASE_URL=postgres://... go run ./cmd/seed/ --clear --scenario=full

# 静音モード
DATABASE_URL=postgres://... go run ./cmd/seed/ --quiet
```

## Docker Compose での使用

```bash
docker-compose exec api sh -c "DATABASE_URL=\$DATABASE_URL ./edr-seed --scenario=full"
```

## シナリオ説明

| シナリオ | 説明 | エージェント | アラート |
|---------|------|------------|---------|
| `full` | 全機能デモ用フルデータ | 50 | 200 |
| `ransomware` | LockBit 3.0 攻撃キャンペーン | 20 | 10 |
| `apt` | APT29 (Cozy Bear) TTP | 30 | 10 |
| `insider` | 内部脅威・UEBA異常検知 | 10 | 8 |
| `minimal` | 最小限のデモデータ | 5 | 10 |
