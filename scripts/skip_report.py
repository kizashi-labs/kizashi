#!/usr/bin/env python3
"""走らなかったテストを数えて出す。上限を超えたら落とす。

    go test -json ./... | python3 scripts/skip_report.py --max-skips 8

**`ok` の行は、通った検査と走らなかった検査を区別しません。** このリポジトリの
検査の多くは `TEST_DATABASE_URL` が無ければ `t.Skip` します。設定せずに
`go test ./...` を回すと、891 本が飛んだうえで全パッケージが `ok` を出します。

このキャンペーンで見つけた欠陥は、ほぼ全部その 891 本の側にありました:

  - 保管時暗号化が、書き込み側も読み出し側も一度も動いていなかった
  - `ai_attack_chain` に値が入るとアラート一覧が0件になる
  - エージェントの付かないアラート1件が一覧全体を落とす
  - テナントを名乗らないリクエストが他テナントの端末を隔離できる

どれも DB を当てて初めて出ました。**当てていないことが見えていれば、
もっと早く出ていたはずです。**

出すのは3つ:

  - 走った / 通った / 落ちた / 飛んだ の数
  - 飛んだ理由ごとの件数（多い順）
  - 上限を超えていないか

理由は正規化します。`TEST_DATABASE_URL not set - skipping DB integration tests`
が 400 行並んでも、読む人が得る情報は「DB が無い、400 本」だけです。
"""
import argparse
import json
import re
import sys
from collections import Counter

# 理由の正規化。実行ごとに変わる部分（UUID、パス、秒数）を潰します。
# 潰さないと同じ理由が別々に数えられ、一覧が理由ではなく実行ログになります。
_NOISE = [
    (re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), '<uuid>'),
    (re.compile(r'\b\d+(\.\d+)?(ms|s|m)\b'), '<dur>'),
    (re.compile(r'/[^\s:]+/'), '<path>/'),
    (re.compile(r'\b\d{3,}\b'), '<n>'),
]


def normalize(reason: str) -> str:
    """Collapse run-specific detail so identical causes group together."""
    r = reason.strip()
    # `foo_test.go:31: ` のような位置情報は理由ではありません。
    r = re.sub(r'^\S+_test\.go:\d+:\s*', '', r)
    for pat, repl in _NOISE:
        r = pat.sub(repl, r)
    return r.strip()


def parse(lines) -> tuple[Counter, dict[str, str], Counter, list[str]]:
    """Read `go test -json` events.

    Returns (outcomes, skip reason per test, reason counts, broken packages).

    出力に混ざる非 JSON の行は読み飛ばします。**ただしパッケージ単位の
    失敗は数えます。**

    ここを読み飛ばしていて、実際に見落としました。`agent` を
    `-tags ebpf` で測ったとき、この道具は「856 本中 飛んだ 1 本」ではなく
    「762 本中 飛んだ 1 本」を出し、**きれいに見えました。** 実際には
    2パッケージが `[build failed]` で落ちていて、94 本が「飛んだ」でも
    「落ちた」でもなく、**最初から存在しませんでした。**

    ビルドできなかったパッケージと、テストの無いパッケージは、
    テスト事象を1つも出しません。数えるだけの道具からは同じ姿です ——
    このリポジトリで何度も出てきた形が、道具の側にもありました。
    """
    outcomes = Counter()
    skip_reason: dict[str, str] = {}
    output: dict[str, list[str]] = {}
    pkg_failed: set[str] = set()
    pkg_has_test: set[str] = set()

    for line in lines:
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue

        pkg = ev.get('Package', '')
        test = ev.get('Test')
        action = ev.get('Action')

        if not test:
            # パッケージ単位の事象。テストの数には入れませんが、
            # **失敗だけは覚えます。**
            if action == 'fail':
                pkg_failed.add(pkg)
            continue

        key = f"{pkg}.{test}"
        if action == 'output':
            output.setdefault(key, []).append(ev.get('Output', ''))
        elif action in ('pass', 'fail', 'skip'):
            outcomes[action] += 1
            pkg_has_test.add(pkg)
            if action == 'skip':
                skip_reason[key] = _reason_from(output.get(key, []))

    # テスト事象を1つも出さずに落ちたパッケージ ＝ ビルドできていません
    # （テストが落ちたのなら、そのテストの fail 事象が出ています）。
    broken = sorted(pkg_failed - pkg_has_test)
    return outcomes, skip_reason, Counter(skip_reason.values()), broken


def _reason_from(output_lines: list[str]) -> str:
    """Pull the skip message out of a test's captured output.

    最後の `--- SKIP` より前で、いちばん近い中身のある行が理由です。
    見つからなければ「理由なし」——**それ自体が言うべきことです。**
    t.Skip() を引数なしで呼ぶと、なぜ飛んだのか誰にも分かりません。
    """
    for line in reversed(output_lines):
        s = line.strip()
        if not s or s.startswith('---') or s.startswith('===') or s.startswith('ok '):
            continue
        return normalize(s)
    return '(理由が書かれていません)'


def report(outcomes: Counter, reasons: Counter, max_skips: int | None,
           broken: list[str] | None = None) -> int:
    broken = broken or []
    total = outcomes['pass'] + outcomes['fail'] + outcomes['skip']
    print()
    print('=== 走らなかったテスト ===')
    print(f'  合計 {total} 本 — 通過 {outcomes["pass"]} / 失敗 {outcomes["fail"]} '
          f'/ **飛んだ {outcomes["skip"]}**')

    if reasons:
        print()
        for reason, n in reasons.most_common():
            print(f'  {n:>5}  {reason}')

    if broken:
        print()
        print(f'  **ビルドできなかったパッケージ {len(broken)} 個。**')
        print('  そこにあるテストは「飛んだ」にも「落ちた」にも数えられません ——')
        print('  最初から1本も存在しないので、上の合計にも入っていません。')
        for p in broken:
            print(f'    {p}')

    if max_skips is None:
        return 1 if broken else 0

    print()
    if broken:
        print(f'NG: {len(broken)} 個のパッケージがビルドできていません。'
              '本数を数える前に、そちらを直してください。')
        return 1
    if outcomes['skip'] > max_skips:
        print(f'NG: 飛んだテストが {outcomes["skip"]} 本です（上限 {max_skips}）。')
        print('    DB が要るなら scripts/local-db.sh up を先に走らせてください。')
        print('    増えたのが意図なら、理由とともに上限を上げてください。')
        return 1
    if outcomes['skip'] < max_skips:
        print(f'NG: 飛んだテストが {outcomes["skip"]} 本まで減りました。'
              f'上限を {outcomes["skip"]} に下げてください。')
        print('    **下げないと、次に増えた分がこの差に隠れます。**')
        return 1
    print(f'ok: 飛んだテストは {outcomes["skip"]} 本（上限どおり）')
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--max-skips', type=int, default=None,
                    help='この本数ちょうどでなければ落とします（増減の両方）')
    args = ap.parse_args()

    outcomes, _, reasons, broken = parse(sys.stdin)
    if outcomes['pass'] + outcomes['fail'] + outcomes['skip'] == 0 and not broken:
        print('NG: テストの事象が1つも読めませんでした。'
              '`go test -json` の出力を渡していますか', file=sys.stderr)
        return 1
    return report(outcomes, reasons, args.max_skips, broken)


if __name__ == '__main__':
    sys.exit(main())
