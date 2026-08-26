#!/usr/bin/env python3
"""スナップショットを削り終えたあと、生成器が **1 回だけ**呼ぶところ。

    python3 scripts/after_snapshot.py              # 何をするか見るだけ
    python3 scripts/after_snapshot.py --apply      # 実際に書き換える
    python3 scripts/after_snapshot.py --apply --generator
                                                   # 生成器から呼ぶとき

## なぜ 1 本にまとめるか

`docs/ci/本流へ渡す作業一覧.md` が本流に頼んでいることのうち、§1-1 と
§1-3 は結局「**順番どおりに 3 つ呼ぶ**」だけです。順番は散文で書いて
ありました。散文の順番は、**読み飛ばされても何も落ちません。**

ここでは順番をコードにします。生成器側の変更は 1 行になります。

    1  handover_timeouts.py --restore    消えた timeout-minutes 49 件を戻す
    2  recalibrate_ratchets.py --apply   ラチェットの固定値を実測まで下げる
    3  reanchor_mutations.py --apply     下げた値を指す pattern を追随させる

## 2 → 3 の順は入れ替えられません

固定値を下げると、その値を含む変異仕様書の pattern が当たらなくなります
（`backgroundFailedCount = 76` → `= 69`）。**3 を先に走らせると、まだ
動いていない値に合わせて何もせず、そのあと 2 が値を下げて仕様書が
死にます。** 当たらなくなった仕様書は、走らせても全 SKIP で緑を返す
だけの文書です。

なので **2 が失敗したら 3 は走らせません。** 下がっていない値に pattern を
合わせても意味が無く、「合わせた」という記録だけが残るほうが悪いからです。

## 落ちたことを飲み込みません

3 つのどれかが 0 以外を返したら、ここも 0 以外を返します。**まとめて
報告します** —— 1 つ目で止めると、2 つ目以降にも問題があることが
次の生成まで分かりません（ただし 2 → 3 の依存だけは上記のとおり）。

## `--generator` は 3 の落ちを致命にしません

生成器から呼ぶときだけ付けます。**生成器の経路では、3（pattern の付け替え）に
直せない残りがあるのが正常**だからです —— 生成器は台帳から項目を刈り、
ファイルごと落とすので、そこを名指ししていた pattern は「数字が動いた」では
なく「中身ごと無い」になります。付け替えようがありません。

**見逃すわけではありません。** 残りは生成器が
`scripts/public-snapshot/adjust-mutations.py` で 1 件ずつ名指しし、
`run_mutations.py --check` が最終的に判定します。**`--generator` を付けても
1 と 2 の落ちは致命のままです。**

この旗が無いと、生成器は 3 の終了コードで落ちます —— **分ける前に落ちるので、
何が「直せない」で何が「この配置には無い」なのかが出ないまま止まります。**

## 終了コード

    0  3 つとも成功した（`--generator` のときは 3 の落ちを数えません）
    1  どれかが失敗した。**何が落ちたかを列挙します**
"""
from __future__ import annotations

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# (名前, スクリプト, 適用するときの引数, 見るだけのときの引数)
#
# **見るだけの側も必ず用意します。** 「試しに呼ぶ」経路が無い道具は、
# 生成器に入れる前に確かめられません —— 確かめられないものは入りません。
STEPS = [
    ('timeout-minutes を戻す', 'handover_timeouts.py', ['--restore'], ['--check']),
    ('ラチェットの固定値を下げる', 'recalibrate_ratchets.py', ['--apply'], []),
    ('変異仕様書の pattern を追随させる', 'reanchor_mutations.py', ['--apply'], []),
]

# 3 は 2 の結果に乗ります。2 が落ちたら 3 は走らせません（上記）。
DEPENDS_ON = {2: 1}


def run_step(script: str, args: list[str]) -> int:
    """1 本走らせて終了コードを返す。出力はそのまま流します。"""
    return subprocess.call([sys.executable, os.path.join(HERE, script)] + args)


# 3 は「付け替え」。生成器の経路では直せない残りがあるのが正常（docstring 参照）。
REANCHOR_STEP = 2


def main(argv: list[str]) -> int:
    apply = '--apply' in argv[1:]
    generator = '--generator' in argv[1:]
    if [a for a in argv[1:] if a not in ('--apply', '--generator')]:
        print(__doc__)
        return 1

    print('スナップショット後の調整を走らせます'
          f'（{"書き換えます" if apply else "見るだけです"}）\n')

    failed: dict[int, str] = {}
    skipped: list[str] = []
    for i, (label, script, apply_args, dry_args) in enumerate(STEPS):
        need = DEPENDS_ON.get(i)
        if need is not None and need in failed:
            skipped.append(label)
            print(f'── {i + 1}. {label} —— **走らせません。**'
                  f' {STEPS[need][0]} が落ちたからです\n')
            continue
        print(f'── {i + 1}. {label}')
        code = run_step(script, apply_args if apply else dry_args)
        print()
        if code != 0:
            if generator and i == REANCHOR_STEP:
                # **落ちたことは出します。数えないだけです。**
                print(f'   （{script} は {code} を返しましたが、生成器の経路では'
                      f'残りが出るのが正常です。名指しと判定は呼び出し側が'
                      f'行います）\n')
                continue
            failed[i] = f'{script} が {code} を返しました'

    if not failed and not skipped:
        print('3 つとも成功しました' if apply else
              '見るだけの実行は 3 つとも成功しました'
              '（`--apply` を付けると書き換えます）')
        return 0

    print('落ちたものがあります:\n')
    for i, why in sorted(failed.items()):
        print(f'  - {STEPS[i][0]}: {why}')
    for label in skipped:
        print(f'  - {label}: 前の段が落ちたので走らせていません')
    print('\n**この配置は、この 3 つが揃って初めて元の木と同じになります。**'
          '\n落ちたものを直してから、もう一度呼んでください。')
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
