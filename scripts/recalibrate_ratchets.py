#!/usr/bin/env python3
"""ラチェットの固定値を、実測に合わせて**下げる**。

    python3 scripts/recalibrate_ratchets.py            # 何をするか見るだけ
    python3 scripts/recalibrate_ratchets.py --apply    # 実際に書き換える

## なぜ要るか

このリポジトリは本流のスナップショットで、生成時に有償機能のコードを
落とします。落とした分だけ「捨てている書き込み」「ルートの無い呼び出し」
といった実測値が下がるので、本流に合わせた固定値がそのまま残ると
**ラチェットが「減りました。下げてください」と言い続けます。**

生成のたびに人が 1 つずつ測り直すのは現実的ではありません。#70 はそれを
理由にラチェット 16 本を配布から外しました（issue #72）。この道具は
その手作業を自動化して、検査を残したまま負担だけを消すためのものです。

## 下げるだけです。**上げません。**

**これがこの道具のいちばん大事な性質です。**

  下がった  実測が固定値を下回った。コードを削ったか、直したか。
            固定値を下げないと、次に増えても気づけません。**自動で下げます。**

  上がった  実測が固定値を上回った。**新しく死んだ呼び出しか、新しく
            捨てられた書き込みです。** ここを自動で埋めると、劣化を
            記録して緑にするだけの道具になります。**落として、人に渡します。**

実例があります。#70 の取り込みで `/login` の SSO 取得が戻り、ルートの
無い読み取りが 132 → 133 に増えました。あれを自動で 133 にしていたら、
「宛先の無い呼び出しが1本増えた」という事実はどこにも残りませんでした。

## 何を自動で下げられるか

検査が出す文言のうち、**定数名と新しい値の両方を含むもの**だけです。

    MOCK_LEAK_CEILING を 3 に下げてください      ← 下げられる
    ルートの無い読み取りが 129 まで減りました      ← 名前が無いので下げられない

後者は「手で下げてください」として一覧に出します。**黙って飛ばしません** ——
飛ばすと、下げ忘れた固定値が実測から離れたまま残り、その間に増えた分が
見えなくなります。

## 使う側（生成器）へ

スナップショットを削り終えたあと、`--apply` で 1 度呼んでください。
終了コードは:

    0  すべて実測に合っている（下げた／下げるものが無かった）
    1  自動で下げられない指摘が残っている。**人の判断が要ります**
    2  検査そのものが走らなかった（前提が足りない）

**検査が赤いまま 0 を返しません。** 落ちているのに下げられる指摘が
1 つも取れなければ「説明できない失敗」として挙げ、`--apply` で下げた
場合は下げたあとにもう一度走らせて緑を確かめます。作っている途中で
一度これを踏みました —— 上限を実測より下げた状態で「すべての固定値が
実測に合っています」と 0 を返しました。
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 走らせる検査。**ここに無いものは測りません。**
SUITES = [
    ('go', 'server', ['go', 'test', './internal/api/handlers/', './internal/scheduler/',
                      './internal/store/', './internal/tick/', './internal/detection/',
                      './internal/metrics/']),
    ('vitest', 'frontend', ['npx', 'vitest', 'run']),
]

# 「<定数名> を <数> に下げてください」。定数名は英大文字と数字と _ か、
# 小文字混じりの Go の識別子（testOnlyCeiling）。
NAMED = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*を\s*(\d+)\s*に下げてください')

# 定数の宣言。TypeScript の `const X = 12` と Go の `X = 12` / `const X = 12`。
def decl_re(name: str) -> re.Pattern:
    return re.compile(
        r'^(?P<head>\s*(?:(?:export\s+)?const\s+)?' + re.escape(name) +
        r'(?:\s*:\s*number)?\s*=\s*)(?P<value>\d+)(?P<tail>\s*(?://.*)?)$',
        re.M)


def run(cwd: str, cmd: list[str]) -> tuple[int, str]:
    # **復号で落とさない。** 走らせる相手（go test / vitest）の出力は、その機械の
    # 既定エンコーディングで返る。UTF-8 決め打ちだと日本語 Windows (cp932) で
    # 例外になり、**「上がる方向のずれが出た」とまったく同じ形で失敗する** ——
    # 実際にそう読み違えた。読めない文字は捨てて、判定そのものは続ける。
    # Windows では `npx` の実体が `npx.cmd` で、`shell=False` の CreateProcess は
    # 拡張子を補わない（WinError 2）。**スナップショットの生成は Windows で
    # 行うので、ここで起動できないと較正そのものが走らない。** 見つからなければ
    # 実体を探し直す。
    argv = list(cmd)
    if os.name == 'nt':
        found = shutil.which(argv[0])
        if found:
            argv[0] = found
    try:
        p = subprocess.run(argv, cwd=os.path.join(ROOT, cwd),
                           capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
    except FileNotFoundError:
        # 「走らせられなかった」を「ずれ 0」と混ぜない。呼び出し側が読める形で返す。
        return 127, f'{argv[0]} を起動できませんでした（この機械には入っていません）'
    return p.returncode, (p.stdout or '') + (p.stderr or '')


def find_decl(name: str) -> tuple[str, int] | None:
    """その定数を宣言しているファイルと現在の値。見つからなければ None。"""
    rx = decl_re(name)
    for base in ('server', 'frontend/tests', 'frontend/lib', 'scripts'):
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, base)):
            dirnames[:] = [d for d in dirnames
                           if d not in ('node_modules', '.next', 'vendor', '.git')]
            for fn in filenames:
                if not fn.endswith(('.go', '.ts', '.tsx')):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    with open(path, encoding='utf-8') as fh:
                        src = fh.read()
                except (OSError, UnicodeDecodeError):
                    continue
                m = rx.search(src)
                if m:
                    return path, int(m.group('value'))
    return None


def lower(path: str, name: str, new: int) -> bool:
    with open(path, encoding='utf-8') as fh:
        src = fh.read()
    rx = decl_re(name)
    m = rx.search(src)
    if not m:
        return False
    out = src[:m.start()] + m.group('head') + str(new) + m.group('tail') + src[m.end():]
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(out)
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--apply', action='store_true',
                    help='実際に書き換える（既定は表示のみ）')
    args = ap.parse_args()

    lowered: list[str] = []
    manual: list[str] = []
    raised: list[str] = []
    failed_to_run: list[str] = []
    unexplained: list[str] = []

    for label, cwd, cmd in SUITES:
        code, out = run(cwd, cmd)
        if code == 0:
            print(f'  ok    {label}: 実測に合っています')
            continue
        before = len(lowered) + len(manual) + len(raised)
        # 走らなかった（ビルド失敗・依存不足・機械の都合）と、判定が落ちたのは別物。
        #
        # `permission denied` と `no space left` をここに入れてあるのは、実際に
        # 踏んだため。**module cache の一部が root 所有**（過去の sudo go の
        # 名残）で go がダウンロードを書けず、検査は 1 つも走らないまま
        # 非ゼロで返った。あのとき出たのは「下げたあとも落ちています」で、
        # **木の劣化とまったく同じ形**だった —— 機械の都合を劣化として
        # 読んでしまうと、直すべきでないものを直しに行く。
        if any(k in out for k in ('build failed', 'Cannot find', 'command not found',
                                  'を起動できませんでした',
                                  'permission denied', 'no space left on device')):
            failed_to_run.append(f'{label}: 検査が走っていません'
                                 f'（ビルド失敗・依存不足・書き込み権限などの機械の都合）')
            continue

        seen: set[tuple[str, int]] = set()
        for m in NAMED.finditer(out):
            name, new = m.group(1), int(m.group(2))
            if (name, new) in seen:
                continue
            seen.add((name, new))
            found = find_decl(name)
            if not found:
                manual.append(f'{label}: {name} を {new} に下げる（宣言が見つかりません）')
                continue
            path, cur = found
            rel = os.path.relpath(path, ROOT)
            if new == cur:
                continue
            if new > cur:
                # **上がる方向。埋めません。**
                raised.append(f'{rel}: {name} {cur} → {new}（増えています）')
                continue
            if args.apply and lower(path, name, new):
                lowered.append(f'{rel}: {name} {cur} → {new}')
            else:
                lowered.append(f'{rel}: {name} {cur} → {new}（--apply で書き換え）')

        # **上がる方向の指摘。** `ceilingProblem` の増加側は
        # 「◯◯が N から M に増えています」で、定数名を載せていない。
        # NAMED では拾えないので、ここまで来ると「下げられる指摘が
        # 0 件」に落ち、**上がったのに「下げすぎた可能性」と言う。**
        # 実測 (2026-08-22): NAV_PENDING が 59 から 60 に増えた回が
        # そう出た。名前は分からないので数だけ記録し、**埋めない。**
        for line in out.splitlines():
            if re.search(r'から \d+ に増えています', line):
                raised.append(f'{label}: {line.strip()[:160]}')

        # 名前を含まない指摘。**黙って捨てません。**
        for line in out.splitlines():
            if '下げてください' in line and not NAMED.search(line):
                manual.append(f'{label}: {line.strip()[:160]}')

        # **落ちているのに、説明が1つも取れなかった場合。**
        #
        # ここを黙って通すと、この道具は「検査が赤いまま緑を返す装置」に
        # なります —— このリポジトリが潰そうとしている形そのものです。
        # 実際に一度そうなりました（上限を実測より下げた状態で「すべての
        # 固定値が実測に合っています」と exit 0 を返した）。
        if len(lowered) + len(manual) + len(raised) == before:
            # **走らせ方が落ちた回と、判定が落ちた回は別物。**
            #
            # ここに来るのは「非ゼロで返ったのに、下げられる指摘が 1 つも
            # 取れなかった」回。上限を下げすぎた（＝劣化した）疑いは本物だが、
            # **走り切っていないだけの回も同じ形で来る。**
            #
            # 実測 (2026-08-22、生成器の Windows): vitest が
            #
            #	Test Files  35 passed (35)
            #	Tests      391 passed (391)
            #	Errors       7 errors
            #	[vitest-pool-runner]: Timeout waiting for worker to respond
            #
            # と返した。**この 35 は走ったぶんだけの数**で、同じ木の次の生成は
            # 42 ファイルだった —— 起動に失敗した 7 ファイルは、まとめ行の
            # どこにも出ない。まとめ行を「全件通った」と読んではいけない。
            #
            # 待ち時間は vitest の中の定数（cli-api の START_TIMEOUT = 6e4、
            # WORKER_START_TIMEOUT = 9e4）で、設定から変えられない。
            # `testTimeout` はテストの中身の上限なので、ここには効かない。
            RUNNER_BROKE = (
                'Failed to start', 'Timeout waiting for worker to respond',
                'Timeout starting', 'Worker exited unexpectedly',
            )
            if any(k in out for k in RUNNER_BROKE):
                failed_to_run.append(
                    f'{label}: worker を起動できず、走り切っていません。'
                    f'まとめ行の件数は走ったぶんだけなので、緑の証拠になりません。'
                    f'**測れていません** —— 同じ木で走らせ直してください')
                continue
            claims = [ln.strip()[:160] for ln in out.splitlines()
                      if 'AssertionError' in ln or ln.lstrip().startswith('--- FAIL')]
            unexplained.append(
                f'{label}: 落ちていますが、下げられる指摘が1つも取れませんでした。'
                f'**上限を実測より下げた（＝劣化した）可能性があります。**')
            unexplained.extend(f'    {c}' for c in claims[:5])
            continue

        # 下げたなら、緑になったことを確かめる。**下げっぱなしにしない。**
        if args.apply:
            code2, out2 = run(cwd, cmd)
            if code2 != 0:
                claims = [ln.strip()[:160] for ln in out2.splitlines()
                          if 'AssertionError' in ln or ln.lstrip().startswith('--- FAIL')]
                unexplained.append(f'{label}: 下げたあとも落ちています')
                unexplained.extend(f'    {c}' for c in claims[:5])

    def show(title: str, items: list[str]) -> None:
        if not items:
            return
        print(f'\n{title}')
        for i in sorted(set(items)):
            print(f'  {i}')

    show('下げたもの:' if args.apply else '下げられるもの:', lowered)
    show('**上がっています。自動では埋めません** —— 新しい劣化かどうかを'
         '読んでください:', raised)
    show('自動では下げられません（定数名が文言に無い）。手で下げてください:', manual)
    show('検査が走っていません:', failed_to_run)
    show('**説明できない失敗**（この道具では直せません）:', unexplained)

    if failed_to_run:
        return 2
    if raised or manual or unexplained:
        return 1
    if lowered and not args.apply:
        return 1
    print('\nすべての固定値が実測に合っています')
    return 0


if __name__ == '__main__':
    sys.exit(main())
