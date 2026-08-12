# Changelog

このプロジェクトの主要な変更を記録します。
形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に、
バージョニングは [Semantic Versioning](https://semver.org/lang/ja/) に従います。

## [Unreleased]

## [0.1.0]

初回公開。

### 含まれるもの

- **エージェント** — Linux (eBPF CO-RE)、Windows (ETW)、macOS (ESF / プロセスポーリング)。
  ウォッチドッグによる自動復旧、オフライン時のイベントリングバッファ、mTLS gRPC 送信
- **検知** — ビルトイン Sigma ルール、DB 上の Sigma ルール、状態を持つ振る舞い検知
  （ポートスキャン、DNS トンネリング、ビーコン、認証情報アクセス、横展開、
  ランサムウェアのファイル操作バースト、キルチェーン相関）、YARA（純 Go 実装）、
  IOC 照合、Isolation Forest による異常検知、プロセス系譜分析
- **相関** — MITRE ATT&CK の戦術と時間窓に基づくアラートのインシデント化
- **対応** — ネットワーク隔離、ファイル検疫、プロセス停止、プレイブック、ライブレスポンス
- **コンソール** — Next.js 14 による SOC 画面（アラート、インシデント、エンドポイント、
  脅威ハンティング、ルール管理ほか）
- **SDK** — Python / TypeScript の API クライアント

### 既知の制約

- Windows カーネルドライバ (`agent/driver/windows/prevention/`) と Linux eBPF LSM フック
  は**未検証の PoC**であり、製品ビルドに結線されていません。実運用環境に投入しないでください
- macOS の Endpoint Security Framework サポートには Apple のエンタイトルメント申請が必要です
- `docs/` の大半とコンソールの表示文言は日本語です
