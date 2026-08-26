# 検知能力の測定 — ATT&CK スコアカードと誤検知ソーク

Kizashi は「検知できる」と主張するだけでなく、**測って、劣化したら CI を落とす**。
このディレクトリはその測定資産と回帰ゲートの基準値を置く場所。

## 2 つの測定モード

EDR の良し悪しは 1 つの数字では表せない。攻撃を捕まえる能力と、平常時に鳴らない能力は
別々に測る必要がある。片方だけ良くするのは簡単で、意味がない。

| 測るもの | 何を見るか | 資産 |
|---|---|---|
| **真陽性** — 攻撃を検知できるか | ATT&CK の技法ごとに、実行した攻撃が検知されたか | 本ディレクトリの fixture と baseline |
| **偽陽性** — 攻撃でないものを鳴らさないか | 良性のテレメトリだけを流し、誤検知率（件/1000ホスト/日）を出す | [`tests/fpsoak/`](../../tests/fpsoak) のプロファイル |

誤検知の測定を軽視しないこと。**検知率 100% は、全部にアラートを出せば達成できる。**
現場を殺すのはその後の対応コストで、EDR の実用性はここで決まる。

## 採点の仕組み

`agent/cmd/attack-scorer` が、攻撃の実行ログ（runlog）と検知されたアラート（alerts）を
突き合わせ、ATT&CK の技法単位でスコアカードを出す。**サーバも実 VM も要らない**——
記録済みの入力に対する事後採点なので、誰でも同じ結果を再現できる。

```bash
cd agent && go build -o /tmp/attack-scorer ./cmd/attack-scorer

/tmp/attack-scorer \
  -runlog  docs/results/fixtures/intrusion_runlog.csv \
  -alerts  docs/results/fixtures/intrusion_alerts.json \
  -out     /tmp/scorecard.csv \
  -baseline docs/results/baseline_intrusion.csv \
  -baseline-tol 0
```

`-baseline` を渡すと、基準値より検知が減っていた場合に非ゼロ終了する。
`.github/workflows/attack-scorecard.yml` がこれを 3 つのシナリオに対して実行しており、
**検知ロジックを変更して取りこぼしが増えると PR が落ちる**。

## 収録しているシナリオ

| シナリオ | 性質 | 基準値 |
|---|---|---|
| `intrusion` | 侵入から横展開までの多段チェーン。**部分検知**（全部は捕まらない）が基準 | `baseline_intrusion.csv` |
| `discovery` | 探索バースト。相関アラート 1 件が複数技法をまとめて担当する経路 | `baseline_discovery.csv` |
| `postexploit` | 侵害後の永続化・認証情報アクセス | `baseline_postexploit.csv` |
| `fp_soak` | 誤検知率の基準値（良性フリート） | `baseline_fp_soak.csv` |

`intrusion` の基準値が満点でないのは意図的である。**取りこぼしを 0 と書いた基準値は、
取りこぼしが増えたことを検出できない。** 実測値をそのまま基準にしている。

## 基準値を更新するとき

検知を改善して数字が上がったら、fixture を再採点して baseline を差し替える。
**下がったときに安易に基準値を下げないこと。** それをやると回帰ゲートは意味を失う。
下げる場合は、なぜ下げるのかを PR に書く。

## 公開していないもの

実機で計測した記録（`live-*`）と、そこから得た生のアラートキャプチャは、
測定に使ったホスト名やネットワーク構成を含むため公開していない。
公開しているのは、**そこから作った再現可能な fixture と基準値**である。

自分の環境で実測したい場合は、`agent/cmd/attack-scorer` と
[`tests/fpsoak/`](../../tests/fpsoak) のプロファイルを使えば同じ手順を再現できる。
