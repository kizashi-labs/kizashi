# validate-rules — 検知ルール構文検証 CLI

`rules/sigma/**/*.yml`（Sigma）と `rules/yara/**/*.yar`（YARA）の構文を検証する。
壊れたルールが本番で無言に読み込み失敗する事故を、CI/ローカルの両方でビルド前に検知するために新設した
（`ci.yml` の `rules-validate` ジョブから push/PR ごとに自動実行される）。

## 使用方法

```bash
# server/ ディレクトリから（rules/ を自動検出して上方向に探索する）
go run ./cmd/validate-rules

# rules/ ディレクトリを明示指定
go run ./cmd/validate-rules -dir ../rules
```

成功時は exit code 0 で件数サマリのみ、失敗時は `file: error` 形式で全ファイルを列挙し exit code 1。

## 検証方法

- **Sigma**: 本番と同じ `internal/detection.SigmaEvaluator.LoadRule` でパース・コンパイルする。
  ここで失敗するルールは本番でも読み込みに失敗する。
- **YARA**: 実 `yara` CLI（reference implementation、`apt-get install yara`）で
  `yara -w <rule> <dummy-target>` を実行し構文チェックする（`-w` で警告もエラー扱いに昇格）。
  `yara` が PATH に無い環境（例: ローカル開発機）では、括弧の対応・`condition:` ブロックの有無など
  最小限の構造チェックへフォールバックする（完全な代替ではないが、壊れ方の大半は検知できる）。

YARA を Go の実パーサで検証しない理由: `agent/internal/scanner` に手組みの YARA サブセットパーサが
あるが、これは別 Go モジュール（`github.com/edr-platform/agent`）の `internal/` パッケージであり、
Go の可視性規則上 `server/cmd/*` からは（モジュール構成をどう変えても）import できない。文法を
二重実装するよりも、reference implementation である `yara` CLI に検証を委ねている。

## 関連ドキュメント

- [`docs/検知ルールの二重管理とデプロイ.md`](../../../docs/検知ルールの二重管理とデプロイ.md) §4 —
  本ツールは「構文が壊れていないか」の静的チェックであり、同ドキュメントが扱う
  「実行時に正しく発火するか（到達性・二重エンジンの取り違え）」とは独立したより手前のガード。
