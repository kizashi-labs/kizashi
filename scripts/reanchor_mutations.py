#!/usr/bin/env python3
"""変異仕様書の pattern を、いまの木に合わせて付け替える。

    python3 scripts/reanchor_mutations.py            # 何をするか見るだけ
    python3 scripts/reanchor_mutations.py --apply    # 実際に書き換える

## なぜ要るか

`scripts/mutations/*.py` は「このファイルのこの文字列を、こう書き換える」
という形で検査を壊します。**壊せなくなった仕様書は、走らせても全 SKIP で
緑を返すだけの文書になります。**

対象が動く原因は 2 つあります。どちらも同期のたびに起きます。

  値が変わった    ラチェットの固定値を下げると、その値を含む pattern が
                  当たらなくなる（`backgroundFailedCount = 76` → `= 69`）
  場所が変わった  道具を別ファイルに切り出すと、pattern が指すファイルが
                  変わる（`swallowed-reads.test.ts` → `catch-scan.ts`）

`recalibrate_ratchets.py` が固定値を下げたあと、**その値を参照している
pattern も一緒に動かさないと、下げた瞬間に仕様書が死にます。** 順番に
呼んでください。

## やること

`run_mutations.py --check` が「当たりません」と言った pattern だけを見ます。

  1. その pattern の探索文字列を、木の中から探す
  2. **ちょうど 1 ファイルで見つかったときだけ**、仕様書の対象を差し替える
  3. 数字だけが違うときは、同じ行の数字を読んで pattern の側を合わせる

**2 か所以上で見つかったものは動かしません。** どちらを指していたのかは
文字列からは決まらないので、当てずっぽうで書き換えると「壊しているつもりで
別の場所を壊している」状態になります。それは pattern が当たらないより
悪い —— 当たらなければ落ちますが、別の場所を壊すと緑で通ります。
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS = os.path.join(ROOT, 'scripts', 'mutations')

SKIP_DIRS = {'node_modules', '.next', '.git', 'vendor', 'dist', '.venv'}
EXTS = ('.go', '.ts', '.tsx', '.py', '.md', '.yml', '.yaml', '.sh')


def load_spec(name: str):
    spec = importlib.util.spec_from_file_location(
        f'_reanchor_{name}', os.path.join(SPECS, name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def tree_files() -> list[str]:
    """探索対象。**仕様書自身と、この道具自身を外します。**

    外さないと、pattern は必ず自分を書いている仕様書に一致します。
    最初その状態で動かして、48 件のほとんどが「2 か所以上で一致するので
    決められない」になりました —— **探しているものが自分の影でした。**
    """
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if os.path.relpath(dirpath, ROOT).startswith(os.path.join('scripts', 'mutations')):
            continue
        for fn in filenames:
            if not fn.endswith(EXTS):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), ROOT)
            if rel in ('scripts/reanchor_mutations.py',
                       'scripts/recalibrate_ratchets.py',
                       'scripts/recalibrate_ratchets_test.py',
                       'scripts/run_mutations.py'):
                continue
            out.append(os.path.join(dirpath, fn))
    return out


def find_exact(needle: str, files: list[str]) -> list[str]:
    """その文字列をそのまま含むファイル。"""
    hits = []
    for path in files:
        try:
            with open(path, encoding='utf-8') as fh:
                if needle in fh.read():
                    hits.append(os.path.relpath(path, ROOT))
        except (OSError, UnicodeDecodeError):
            continue
    return hits


def digit_variants(needle: str, files: list[str]) -> list[tuple[str, str]]:
    """数字だけが違う同じ行。(ファイル, 実際の行) を返す。

    `const X = 132` を探して `const X = 133` が見つかる、という形。
    **数字が 1 つだけの pattern に限ります** —— 2 つ以上あると、どれが
    動いたのかが決まりません。
    """
    if len(re.findall(r'\d+', needle)) != 1:
        return []
    rx = re.compile('^' + re.sub(r'\d+', r'(\\d+)', re.escape(needle)
                                 .replace(r'\ ', ' ')) + '$', re.M)
    # re.escape が数字も守るので、エスケープ後に置換し直す
    esc = re.escape(needle)
    esc = re.sub(r'\d+', r'\\d+', esc)
    rx = re.compile('^.*' + esc + '.*$', re.M)
    out = []
    for path in files:
        try:
            with open(path, encoding='utf-8') as fh:
                src = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        for m in rx.finditer(src):
            line = m.group(0)
            if needle in line:
                continue  # そのまま当たっている
            # 同じ形で数字だけ違う行
            cand = re.sub(r'\d+', lambda mm: mm.group(0), line)
            out.append((os.path.relpath(path, ROOT), line.strip()))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true')
    args = ap.parse_args()

    # まず --check に働いてもらう。当たらない pattern はあちらが知っている。
    # 復号で落とさない（recalibrate_ratchets.py の run() と同じ理由）。
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'run_mutations.py'),
                        '--check'], cwd=ROOT, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    if p.returncode == 0:
        print('すべての pattern が当たります。付け替えるものはありません')
        return 0

    files = tree_files()
    names = sorted(f[:-3] for f in os.listdir(SPECS)
                   if f.endswith('.py') and not f.startswith('_'))

    moved: list[str] = []
    drifted: list[str] = []
    ambiguous: list[str] = []
    unknown: list[str] = []

    for name in names:
        try:
            cases = load_spec(name).CASES
        except Exception as e:  # noqa: BLE001
            unknown.append(f'{name}: 仕様書を読めません: {e}')
            continue
        src_path = os.path.join(SPECS, name + '.py')
        with open(src_path, encoding='utf-8') as fh:
            spec_src = fh.read()
        changed = False

        for rel, old, _new, label in cases:
            path = os.path.join(ROOT, rel)
            if os.path.exists(path):
                with open(path, encoding='utf-8') as fh:
                    if old in fh.read():
                        continue  # 当たっている

            hits = find_exact(old, files)
            if len(hits) == 1 and hits[0] != rel:
                moved.append(f'{name}: {label[:44]} … {rel} → {hits[0]}')
                continue
            if len(hits) > 1:
                ambiguous.append(f'{name}: {label[:44]} … {len(hits)} か所で一致: {hits[:3]}')
                continue

            var = digit_variants(old, files)
            uniq = {v[1] for v in var}
            if len(uniq) == 1:
                actual = var[0][1]
                drifted.append(f'{name}: {label[:44]}\n        旧 {old.strip()[:90]}\n'
                               f'        新 {actual[:90]}  ({var[0][0]})')
                if args.apply and old in spec_src:
                    spec_src = spec_src.replace(old, actual, 1)
                    changed = True
                continue
            if len(uniq) > 1:
                ambiguous.append(f'{name}: {label[:44]} … 数字違いが {len(uniq)} 通り')
                continue

            unknown.append(f'{name}: {label[:60]} … 木のどこにも見つかりません')

        if changed and args.apply:
            with open(src_path, 'w', encoding='utf-8') as fh:
                fh.write(spec_src)

    def show(title: str, items: list[str]) -> None:
        if not items:
            return
        print(f'\n{title}  ({len(items)} 件)')
        for i in items:
            print(f'  {i}')

    show('場所が変わったもの（対象ファイルの差し替えが要る。'
         '**仕様書の定数名を手で直してください**）:', moved)
    show('数字が動いたもの:' if not args.apply else '数字を合わせたもの:', drifted)
    show('**決められないもの。動かしません**（2 か所以上で一致）:', ambiguous)
    show('見つからないもの（対象が消えたか、書き換えられました）:', unknown)

    if not args.apply and drifted:
        print('\n--apply を付けると、数字が動いたものだけ書き換えます')
    return 1 if (moved or ambiguous or unknown or (drifted and not args.apply)) else 0


if __name__ == '__main__':
    sys.exit(main())
