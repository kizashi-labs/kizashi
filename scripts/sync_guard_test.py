#!/usr/bin/env python3
"""sync_guard.py の判定そのものを留める。

**この検査は、他の検査が消えたことを見張る最後の一枚です。** これが
黙って通るようになると、以後どの同期も「配布物はすべて残っています」と
報告し、それは正しく見えます。**確かめる道具が壊れていることが、
いちばん高くつきます。**

木がきれいなあいだ、落ちる枝は一度も通りません。汚した木を作って
渡さないと確かめられないので、ここでは最小の木を組み立てます。

`python3 scripts/sync_guard_test.py` で走ります。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import sync_guard as G  # noqa: E402


def write(root: str, rel: str, text: str) -> None:
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(text)


def workflow(job: str, timeout: int | None, timed_steps: int,
             extra: str = '') -> str:
    """1 ジョブのワークフロー。`timed_steps` 本だけ step 側にも上限を置く。"""
    head = f'name: T\non:\n  push:\njobs:\n  {job}:\n    runs-on: ubuntu-latest\n'
    if timeout is not None:
        head += f'    timeout-minutes: {timeout}\n'
    head += '    steps:\n'
    for i in range(timed_steps):
        head += (f'      - name: fetch {i}\n        timeout-minutes: 10\n'
                 f'        run: echo {i}\n')
    head += '      - name: work\n        run: echo work\n'
    return head + extra


EBPF_RUN = """      - name: Commit binary to downloads/
        run: |
          # `git reset --hard` を挟む再試行でも消えるので、ループの中で作ります。
          for i in 1 2 3 4 5; do
            mkdir -p downloads
            cp agent/x downloads/x
            git commit -m x && break
            git fetch origin main
            git reset --hard origin/main
          done
"""

LINT_RUN = """      - name: Validate
        run: |
          python3 - <<'PY'
          if "timeout-minutes" not in job:
              problems.append("...")
          else:
              t = job["timeout-minutes"]
              if t > 60:
                  problems.append("...")
          PY
"""

VERIFY_SH = """#!/usr/bin/env bash
section "workflows"
python3 - <<'WFLINT'
if "timeout-minutes" not in job:
    problems.append("...")
elif job["timeout-minutes"] > 60:
    problems.append("...")
WFLINT
"""


GUARD_YML = """name: Sync Guard
on:
  pull_request_target:
    branches: [main]
permissions:
  contents: read
jobs:
  distribution:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@aaa
        with:
          persist-credentials: false
      - name: head
        uses: actions/checkout@aaa
        with:
          ref: sha
          path: head
          persist-credentials: false
      - name: Install PyYAML
        timeout-minutes: 10
        run: pip install pyyaml
      - name: self
        run: python3 scripts/sync_guard_test.py
      - name: check
        run: python3 scripts/sync_guard.py head
"""


def build_clean(root: str) -> None:
    """すべての約束を満たす最小の木。"""
    write(root, '.github/workflows/workflow-lint.yml',
          'name: L\non:\n  push:\njobs:\n  lint:\n'
          '    runs-on: ubuntu-latest\n    timeout-minutes: 10\n'
          '    steps:\n' + LINT_RUN)
    write(root, '.github/workflows/agent-ebpf.yml',
          workflow('build-ebpf', 20, G.STEP_TIMEOUT_FLOOR[
              '.github/workflows/agent-ebpf.yml'], EBPF_RUN))
    write(root, G.GUARD_WORKFLOW, GUARD_YML)
    for rel, floor in G.STEP_TIMEOUT_FLOOR.items():
        if rel.endswith('agent-ebpf.yml') or rel == G.GUARD_WORKFLOW:
            continue
        write(root, rel, workflow(os.path.basename(rel)[:-4], 30, floor))
    write(root, G.VERIFY, VERIFY_SH)
    for rel in G.RATCHETS + G.RECALIBRATORS + G.SELF:
        # .yml は上の STEP_TIMEOUT_FLOOR の輪で、上限つきに作ってあります。
        if not rel.endswith('.yml'):
            write(root, rel, '// 中身は見ていません\n')


class GuardCase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        build_clean(self.root)

    def problems(self) -> list[str]:
        out: list[str] = []
        for fn in (G.job_timeouts, G.step_timeouts, G.ebpf_mkdir,
                   G.guard_is_inert):
            out += fn(self.root)
        out += G.markers(self.root, G.WORKFLOW_LINT, G.WORKFLOW_LINT_MARKERS, '')
        out += G.markers(self.root, G.VERIFY, G.VERIFY_MARKERS, '')
        out += G.files_exist(self.root, G.RATCHETS, '')
        out += G.files_exist(self.root, G.RECALIBRATORS, '')
        out += G.files_exist(self.root, G.SELF, '')
        return out

    def assertFires(self, needle: str) -> None:
        found = self.problems()
        self.assertTrue(found, '**汚した木が通りました。**')
        self.assertTrue(any(needle in p for p in found),
                        f'{needle!r} を含む指摘がありません: {found}')


class TestTheCleanTreePasses(GuardCase):
    def test_nothing_is_reported(self):
        """**ここが落ちると、以後どの汚れも「1 件」に埋もれます。**"""
        self.assertEqual(self.problems(), [])


class TestJobTimeouts(GuardCase):
    def test_a_removed_job_timeout_fires(self):
        write(self.root, '.github/workflows/ci.yml', workflow('ci', None, 10))
        self.assertFires('timeout-minutes が消えています')

    def test_a_raised_ceiling_fires(self):
        write(self.root, '.github/workflows/ci.yml', workflow('ci', 90, 10))
        self.assertFires('90 分です')

    def test_an_empty_workflow_directory_fires(self):
        """**「ワークフローが無い」は「全部緑」に見えます。**"""
        shutil.rmtree(os.path.join(self.root, '.github/workflows'))
        self.assertFires('.github/workflows/')

    def test_broken_yaml_fires(self):
        write(self.root, '.github/workflows/ci.yml', 'jobs:\n  - [unclosed\n')
        self.assertFires('ci.yml')


class TestStepTimeouts(GuardCase):
    def test_wholesale_removal_fires(self):
        write(self.root, '.github/workflows/ci.yml', workflow('ci', 30, 0))
        self.assertFires('10 本から 0 本')

    def test_one_missing_step_fires(self):
        write(self.root, '.github/workflows/ci.yml', workflow('ci', 30, 9))
        self.assertFires('10 本から 9 本')

    def test_more_than_the_floor_is_fine(self):
        """**足す向きは止めません。** 上限を増やすのは劣化ではありません。"""
        write(self.root, '.github/workflows/ci.yml', workflow('ci', 30, 12))
        self.assertEqual(G.step_timeouts(self.root), [])


class TestTheCheckItself(GuardCase):
    def test_a_deleted_workflow_lint_fires(self):
        os.unlink(os.path.join(self.root, G.WORKFLOW_LINT))
        self.assertFires('workflow-lint.yml が消えています')

    def test_a_gutted_workflow_lint_fires(self):
        """**ファイルがあることと、判定が残っていることは別です。**

        #70 は workflow-lint.yml を残したまま、中の 28 行だけを消しました。
        """
        write(self.root, G.WORKFLOW_LINT,
              'name: L\non:\n  push:\njobs:\n  lint:\n'
              '    runs-on: ubuntu-latest\n    timeout-minutes: 10\n'
              '    steps:\n      - run: echo ok\n')
        self.assertFires('timeout-minutes の欠落を落とす枝')

    def test_a_gutted_verify_sh_fires(self):
        write(self.root, G.VERIFY, '#!/usr/bin/env bash\necho ok\n')
        self.assertFires('workflow-lint の写し')


class TestTheRatchets(GuardCase):
    def test_a_deleted_ratchet_fires(self):
        os.unlink(os.path.join(self.root, G.RATCHETS[0]))
        self.assertFires(G.RATCHETS[0])

    def test_a_deleted_recalibrator_fires(self):
        os.unlink(os.path.join(self.root, G.RECALIBRATORS[0]))
        self.assertFires(G.RECALIBRATORS[0])

    def test_a_deleted_guard_fires(self):
        """**自分が消されたことを、消された回の PR に出すこと。**

        base 側で走るのでその実行は止まりません。止まるのは次の PR で、
        そのときにはもう誰も見ていません。
        """
        os.unlink(os.path.join(self.root, 'scripts/sync_guard.py'))
        self.assertFires('scripts/sync_guard.py')

    def test_a_deleted_guard_workflow_fires(self):
        os.unlink(os.path.join(self.root, '.github/workflows/sync-guard.yml'))
        self.assertFires('sync-guard.yml')

    def test_all_sixteen_are_named(self):
        """**数ではなく名前で留めます。** 数だと入れ替わりが通ります。"""
        self.assertEqual(len(G.RATCHETS), 16)
        self.assertEqual(len(set(G.RATCHETS)), 16)


class TestTheEbpfMkdir(GuardCase):
    def _ebpf(self, run_body: str) -> None:
        write(self.root, '.github/workflows/agent-ebpf.yml',
              workflow('build-ebpf', 20, 1, run_body))

    def test_a_removed_mkdir_fires(self):
        self._ebpf(EBPF_RUN.replace('            mkdir -p downloads\n', ''))
        self.assertFires('`mkdir -p downloads` が消えています')

    def test_a_mkdir_outside_the_loop_fires(self):
        """**ループの外に出すと、2 回目以降の cp が落ちます。**"""
        body = EBPF_RUN.replace('            mkdir -p downloads\n', '')
        body = body.replace('          for i in 1 2 3 4 5; do',
                            '          mkdir -p downloads\n'
                            '          for i in 1 2 3 4 5; do')
        self._ebpf(body)
        self.assertFires('再試行ループの外にあります')

    def test_a_comment_naming_the_reset_does_not_fire(self):
        """**注釈を数えると、直した場所ほど怒られます。**

        ループの中に置いた理由を書いた注釈が `git reset --hard` に
        触れているので、注釈行を飛ばさないと「reset のほうが先にある」と
        読めます。作っている途中で実際にここで落ちました。
        """
        self.assertEqual(G.ebpf_mkdir(self.root), [])
        with open(os.path.join(self.root, '.github/workflows/agent-ebpf.yml'),
                  encoding='utf-8') as fh:
            before_the_loop = fh.read().split('for i in')[0]
        # 注釈が本当にループより前で reset に触れていること。**ここが
        # 空だと、上の 1 行は何も確かめていません。**
        self.assertIn('git reset --hard', before_the_loop)

    def test_a_missing_step_fires(self):
        self._ebpf('')
        self.assertFires('の step がありません')


class TestTheGuardDoesNotRunPrCode(GuardCase):
    """**`pull_request_target` は base の権限で走ります。**

    PR のコードを1行でも実行したら、そのまま乗っ取られます。Semgrep の
    指摘は「実行していないことを監査してください」で、監査そのものは
    正しい —— **ただし監査は約束で、約束は腐ります。** 半年後に誰かが
    `npm ci` を足したときに落ちる形で留めます。
    """

    def _guard(self, text: str) -> None:
        write(self.root, G.GUARD_WORKFLOW, text)

    def test_the_written_workflow_is_inert(self):
        self.assertEqual(G.guard_is_inert(self.root), [])

    def test_an_extra_run_fires(self):
        """**ここが要です。** 足された命令は、必ず一度読まれること。"""
        self._guard(GUARD_YML + '      - name: build\n        run: npm ci\n')
        self.assertFires('許していない run:')

    def test_a_changed_run_fires(self):
        self._guard(GUARD_YML.replace('python3 scripts/sync_guard.py head',
                                      'bash head/scripts/run.sh'))
        self.assertFires('許していない run:')

    def test_widened_permissions_fire(self):
        self._guard(GUARD_YML.replace('  contents: read',
                                      '  contents: write'))
        self.assertFires('permissions が')

    def test_a_local_action_fires(self):
        self._guard(GUARD_YML.replace('      - name: self\n'
                                      '        run: python3 scripts/sync_guard_test.py\n',
                                      '      - name: self\n'
                                      '        uses: ./head/.github/actions/x\n'))
        self.assertFires('uses が木の中を指しています')

    def test_a_working_directory_in_head_fires(self):
        self._guard(GUARD_YML.replace('      - name: check\n',
                                      '      - name: check\n'
                                      '        working-directory: head\n'))
        self.assertFires('working-directory があります')

    def test_a_checkout_that_keeps_credentials_fires(self):
        self._guard(GUARD_YML.replace('          ref: sha\n'
                                      '          path: head\n'
                                      '          persist-credentials: false\n',
                                      '          ref: sha\n'
                                      '          path: head\n'))
        self.assertFires('persist-credentials: false がありません')

    def test_dropping_the_head_checkout_fires(self):
        """**PR の木を読まない検査は、何も見ていません。**"""
        self._guard(GUARD_YML.replace('          path: head\n', ''))
        self.assertFires('head/ への checkout がありません')


class TestTheExitCode(GuardCase):
    """**約束は終了コードです。** 出力が正しくても 0 を返したら通ります。"""

    def _main(self, root: str) -> int:
        argv, out = sys.argv, sys.stdout
        sys.argv = ['sync_guard.py', root]
        sys.stdout = open(os.devnull, 'w')
        try:
            return G.main()
        finally:
            sys.stdout.close()
            sys.argv, sys.stdout = argv, out

    def test_clean_is_zero(self):
        self.assertEqual(self._main(self.root), 0)

    def test_dirty_is_one(self):
        os.unlink(os.path.join(self.root, G.RATCHETS[0]))
        self.assertEqual(self._main(self.root), 1)

    def test_a_missing_tree_is_one(self):
        """**渡した木が無いときに 0 を返すと、CI は毎回緑になります。**"""
        self.assertEqual(self._main(os.path.join(self.root, 'nope')), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
