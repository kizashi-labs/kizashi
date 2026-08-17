#!/usr/bin/env python3
"""`check-alertmanager.sh` 自身を確かめる。

    python3 scripts/check_alertmanager_test.py

**確かめる道具が壊れていることが、いちばん高くつきます。** 以後どの実行も
「問題なし」と報告し、それは正しく見えます。

見るのは終了コードの約束です。`server/scripts/run_tests.sh` がこれを見て、
「落ちた」と「走らなかった」を別に数えます:

    0  確かめた
    1  確かめて、問題が見つかった
    2  **確かめられなかった**（Alertmanager を取ってこられない、など）

2 を 1 と分けていないと、ネットワークの無い環境で走らせたときに
**「確かめられなかった」が「問題なし」と同じ行になります。**

正しい設定でしか走らせられないと、1 を返す道を一度も通れません。
そのために `REPO` を差し替えられるようにしてあります。
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'check-alertmanager.sh')
REAL_CONFIG = os.path.join(HERE, '..', 'deploy', 'alertmanager.yml')

# 取得済みのバイナリを使い回します。**毎回取りに行くと、ネットワークの
# 都合でこの検査自身が落ちます。**
SHARED_WORK = os.environ.get('WORK', '/tmp/am-check')

failures = []


def check(name, cond, detail=''):
    if cond:
        print(f'  ok    {name}')
        return
    failures.append(name)
    print(f'  NG    {name}')
    if detail:
        for line in detail.strip().splitlines():
            print(f'          {line}')


def run(config_text=None, work=None, version=None, timeout=180):
    """Run the script against a fixture repo, returning (code, stderr)."""
    repo = tempfile.mkdtemp(prefix='am-fixture-')
    try:
        os.makedirs(os.path.join(repo, 'deploy'))
        dst = os.path.join(repo, 'deploy', 'alertmanager.yml')
        if config_text is None:
            shutil.copyfile(REAL_CONFIG, dst)
        else:
            with open(dst, 'w') as f:
                f.write(config_text)
        env = dict(os.environ, REPO=repo, WORK=work or SHARED_WORK)
        if version:
            env['ALERTMANAGER_VERSION'] = version
        p = subprocess.run(['bash', SCRIPT], capture_output=True, text=True,
                           env=env, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def main():
    print('=== check-alertmanager.sh の終了コード ===')

    # 1. 取ってこられないときは 2。**「問題なし」ではありません。**
    empty = tempfile.mkdtemp(prefix='am-empty-')
    try:
        code, out = run(work=empty, version='0.0.0-nonexistent')
        check('取得できないときは 2 (確かめられなかった)', code == 2,
              f'exit={code}\n{out[-600:]}')
        check('取得できないとき、そう言うこと', '確かめられませんでした' in out,
              out[-400:])
        # **理由が原因を指していること。** curl に `-f` が無いと 404 の本文を
        # ファイルに書いて成功で戻り、そのあと tar が落ちます。終了コードは
        # 同じ 2 でも、報告される理由が「展開できません」になり、
        # **原因（取ってこられていない）から離れます。**
        check('取得できないとき、取得の失敗として言うこと',
              '取得できません' in out and '展開できません' not in out,
              out[-500:])
    finally:
        shutil.rmtree(empty, ignore_errors=True)

    if not os.path.isdir(SHARED_WORK):
        print('  -- Alertmanager のバイナリがありません。残りは走らせられません')
        print('     （先に scripts/check-alertmanager.sh を1度走らせてください）')
        failures.append('バイナリが無いので残りを走らせていません')
        return 1

    # 2. 出荷している設定は通ること。
    code, out = run()
    check('出荷している設定は 0 で通る', code == 0, f'exit={code}\n{out[-800:]}')
    check('3つとも見ていること',
          'inhibit' in out and ('通知は届く' in out or '届く' in out),
          out[-400:])

    # 3. スキーマに合わない設定は 1。**「確かめられなかった」ではありません。**
    broken_receiver = open(REAL_CONFIG).read().replace(
        "  receiver: 'edr-slack'", "  receiver: 'does-not-exist'", 1)
    code, out = run(broken_receiver)
    check('存在しない receiver を指す設定は 1', code == 1,
          f'exit={code}\n{out[-800:]}')

    # 4. 通知が届かない設定は 1。
    #    **「ルールを書くこと」と「誰かに届くこと」が別だと言えるのは、
    #    届かない側を通せるときだけです。**
    #    受け口の差し替えは `receiver: 'edr-slack'` を探します。名前を
    #    変えると当たらず、ローカルの受け口には1通も来ません。
    no_delivery = open(REAL_CONFIG).read().replace("'edr-slack'", "'edr-slack2'")
    code, out = run(no_delivery)
    check('通知が届かない設定は 1', code == 1, f'exit={code}\n{out[-900:]}')
    check('届かなかったとき、そう言うこと', '通知が1件も届きませんでした' in out,
          out[-600:])

    # 5. 抑制しない設定は 1。
    #    **inhibit_rules を消すと、API が落ちているあいだ二次アラートも
    #    全部鳴ります。** 設定として正しくても、効いていないことは
    #    起動して初めて分かります。
    src = open(REAL_CONFIG).read()
    start = src.index('inhibit_rules:')
    end = src.index('receivers:')
    no_inhibit = src[:start] + src[end:]
    code, out = run(no_inhibit)
    check('抑制しない設定は 1', code == 1, f'exit={code}\n{out[-800:]}')
    check('抑制していないとき、そう言うこと', '抑制していません' in out, out[-500:])

    # 6. **速くするための差し替えが、出荷値から離れたら落ちること。**
    #    group_wait を 1s に書き換えて待ち時間を削っていますが、出荷値が
    #    変わったのに気づかないまま書き換え続けると、確かめている設定が
    #    出荷している設定ではなくなります。
    drifted = open(REAL_CONFIG).read().replace(
        'group_wait: 30s', 'group_wait: 45s', 1)
    code, out = run(drifted)
    check('出荷の group_wait が変わったら落ちること', code != 0,
          f'exit={code}\n{out[-600:]}')
    check('変わったときに、そう言うこと', 'group_wait' in out, out[-400:])

    print()
    if failures:
        print(f'NG: {len(failures)} 件')
        for f in failures:
            print(f'  - {f}')
        return 1
    print('ok: 終了コードの約束は守られています')
    return 0


if __name__ == '__main__':
    sys.exit(main())
