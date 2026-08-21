#!/usr/bin/env python3
"""handover_timeouts.py の判定そのものを留める。

**この道具は木を書き換えます。** 壊れたまま動くと、`--restore` は
「入れました」と言って何も入れず、`--check` は違いを見落として緑を
返します —— **どちらも、いま防ごうとしている事故そのものです。**

いちばん高くつく壊れ方は「静かに飛ばす」ほうなので、
ここは**飛ばしたら落ちる**ことを重点的に留めます。

`python3 scripts/handover_timeouts_test.py` で走ります。
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import handover_timeouts as H  # noqa: E402

WORKFLOW = '''\
name: Example

on:
  push:

jobs:

  # ジョブの説明。**コメントは残らないといけません。**
  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@abc123

      - name: Install deps
        run: |
          # 深いところにある `- ` は step ではありません
          echo "- name: not a step"
          apt-get install -y thing

      - name: Test
        run: go test ./...

  publish:
    runs-on: ubuntu-latest
    steps:
      - name: Push
        run: echo push
'''

DOC = '''\
# 見出し

## 2. `timeout-minutes` の現物（job 2 + step 1 ＝ 3 件）

### ジョブ 2 件

| ファイル | ジョブ | 分 |
| --- | --- | --- |
| ex.yml | build | 20 |
| ex.yml | publish | 15 |

### step 1 件

説明の段落。**表との間に挟まっていても壊れないこと。**

| ファイル | ジョブ | step | 分 |
| --- | --- | --- | --- |
| ex.yml | build | Install deps | 10 |

> あとがき。
'''


def tree(workflow: str = WORKFLOW, doc: str = DOC) -> str:
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, H.WORKFLOW_DIR))
    with open(os.path.join(root, H.WORKFLOW_DIR, 'ex.yml'), 'w',
              encoding='utf-8') as fh:
        fh.write(workflow)
    os.makedirs(os.path.join(root, os.path.dirname(H.HANDOVER)))
    with open(os.path.join(root, H.HANDOVER), 'w', encoding='utf-8') as fh:
        fh.write(doc)
    return root


def workflow_of(root: str) -> str:
    with open(os.path.join(root, H.WORKFLOW_DIR, 'ex.yml'),
              encoding='utf-8') as fh:
        return fh.read()


class TestRestore(unittest.TestCase):
    """表 → 木。**生成器側で呼ばれるのはこの向きです。**"""

    def test_it_puts_the_table_into_a_tree_that_lost_it(self):
        root = tree()
        self.assertEqual(H.restore(root, *H.parse_doc(DOC)[:2]), [])
        jobs, steps, missing = H.read_tree(root)
        self.assertEqual(missing, [])
        self.assertEqual(sorted(jobs), [('ex.yml', 'build', 20),
                                        ('ex.yml', 'publish', 15)])
        self.assertEqual(steps, [('ex.yml', 'build', 'Install deps', 10)])

    def test_it_keeps_the_comments(self):
        """**`yaml.safe_load` で読んで書き戻すと、説明が全部消えます。**

        消えた説明は、次の同期で値が消される理由になります。
        """
        root = tree()
        H.restore(root, *H.parse_doc(DOC)[:2])
        self.assertIn('# ジョブの説明。', workflow_of(root))
        self.assertIn('# 深いところにある `- ` は step ではありません',
                      workflow_of(root))

    def test_it_is_idempotent(self):
        root = tree()
        H.restore(root, *H.parse_doc(DOC)[:2])
        once = workflow_of(root)
        self.assertEqual(H.restore(root, *H.parse_doc(DOC)[:2]), [])
        self.assertEqual(workflow_of(root), once)

    def test_the_job_ceiling_lands_after_runs_on(self):
        root = tree()
        H.restore(root, *H.parse_doc(DOC)[:2])
        lines = workflow_of(root).split('\n')
        i = lines.index('    runs-on: ubuntu-latest')
        self.assertEqual(lines[i + 1], '    timeout-minutes: 20')

    def test_the_step_ceiling_lands_inside_its_own_step(self):
        """**別の step に入ると、上限は「付いている」のに効きません。**"""
        root = tree()
        H.restore(root, *H.parse_doc(DOC)[:2])
        doc = yaml.safe_load(workflow_of(root))
        steps = doc['jobs']['build']['steps']
        self.assertEqual(steps[1]['name'], 'Install deps')
        self.assertEqual(steps[1]['timeout-minutes'], 10)
        self.assertNotIn('timeout-minutes', steps[0])
        self.assertNotIn('timeout-minutes', steps[2])

    def test_a_renamed_step_is_reported_not_skipped(self):
        """**ここが静かに通ると、上限だけが消えます。**

        本流は step を改名します。名前で入れる以上、見つからない行が
        出るのは想定内で、**想定内だから黙る**のがいちばん危ない。
        """
        renamed = WORKFLOW.replace('- name: Install deps',
                                   '- name: Install dependencies')
        root = tree(workflow=renamed)
        problems = H.restore(root, *H.parse_doc(DOC)[:2])
        self.assertEqual(len(problems), 1)
        self.assertIn('Install deps', problems[0])
        self.assertIn('改名', problems[0])

    def test_a_renamed_job_is_reported_not_skipped(self):
        root = tree(workflow=WORKFLOW.replace('  publish:', '  release:'))
        problems = H.restore(root, *H.parse_doc(DOC)[:2])
        self.assertEqual(len(problems), 1)
        self.assertIn('publish', problems[0])

    def test_a_missing_file_is_reported(self):
        root = tree()
        os.remove(os.path.join(root, H.WORKFLOW_DIR, 'ex.yml'))
        problems = H.restore(root, *H.parse_doc(DOC)[:2])
        self.assertEqual(len(problems), 1)
        self.assertIn('ex.yml', problems[0])

    def test_a_different_value_is_reported_and_not_overwritten(self):
        """**上書きしません。** どちらが正しいかは、ここでは決められません。"""
        changed = WORKFLOW.replace('  build:\n    name: Build\n'
                                   '    runs-on: ubuntu-latest\n',
                                   '  build:\n    name: Build\n'
                                   '    runs-on: ubuntu-latest\n'
                                   '    timeout-minutes: 45\n')
        root = tree(workflow=changed)
        problems = H.restore(root, *H.parse_doc(DOC)[:2])
        self.assertEqual(len(problems), 1)
        self.assertIn('45 分', problems[0])
        self.assertIn('timeout-minutes: 45', workflow_of(root))


class TestCheck(unittest.TestCase):
    """木 ↔ 表。**両方向**を見ること。"""

    def setUp(self):
        self.jobs, self.steps, self.said = H.parse_doc(DOC)

    def test_the_doc_parses(self):
        self.assertEqual(self.jobs, [('ex.yml', 'build', 20),
                                     ('ex.yml', 'publish', 15)])
        self.assertEqual(self.steps, [('ex.yml', 'build', 'Install deps', 10)])
        self.assertEqual(self.said, (2, 1, 3))

    def test_an_old_three_column_step_table_still_parses(self):
        """一度目の `--apply` は、**分の列が無い表**を読むところから始まります。"""
        old = DOC.replace('| ファイル | ジョブ | step | 分 |\n'
                          '| --- | --- | --- | --- |\n'
                          '| ex.yml | build | Install deps | 10 |',
                          '| ファイル | ジョブ | step |\n'
                          '| --- | --- | --- |\n'
                          '| ex.yml | build | Install deps |')
        self.assertEqual(H.parse_doc(old)[1],
                         [('ex.yml', 'build', 'Install deps', 10)])

    def test_no_difference_when_they_agree(self):
        self.assertEqual(
            H.differences(self.jobs, self.steps, self.jobs, self.steps, (2, 1, 3)),
            [])

    def test_a_changed_minute_is_caught(self):
        """**合計は動きません。** 数だけを見ていると、ここは素通りします。"""
        drifted = [('ex.yml', 'build', 20), ('ex.yml', 'publish', 30)]
        out = H.differences(self.jobs, self.steps, drifted, self.steps, (2, 1, 3))
        self.assertEqual(len(out), 2)
        self.assertTrue(any('15' in line for line in out))
        self.assertTrue(any('30' in line for line in out))

    def test_a_stale_total_is_caught(self):
        out = H.differences(self.jobs, self.steps, self.jobs, self.steps, (2, 0, 2))
        self.assertEqual(len(out), 1)
        self.assertIn('実物は job 2 + step 1 ＝ 3 件', out[0])

    def test_a_missing_total_line_is_caught(self):
        out = H.differences(self.jobs, self.steps, self.jobs, self.steps, None)
        self.assertEqual(len(out), 1)


class TestApply(unittest.TestCase):
    """表を書き直す側。**散文を壊さないこと。**"""

    def test_it_rewrites_both_tables_and_all_three_counts(self):
        jobs = [('ex.yml', 'build', 20)]
        steps = [('ex.yml', 'build', 'Install deps', 10),
                 ('ex.yml', 'publish', 'Push', 5)]
        out = H.apply_doc(DOC, jobs, steps)
        self.assertIn('job 1 + step 2 ＝ 3 件', out)
        self.assertIn('### ジョブ 1 件', out)
        self.assertIn('### step 2 件', out)
        self.assertIn('| ex.yml | publish | Push | 5 |', out)
        self.assertNotIn('| ex.yml | publish | 15 |', out)
        # 表のあいだの散文と、あとがき。
        self.assertIn('説明の段落。', out)
        self.assertIn('> あとがき。', out)

    def test_apply_then_check_agree(self):
        jobs, steps, _ = H.read_tree(tree())
        out = H.apply_doc(DOC, jobs, steps)
        d_jobs, d_steps, said = H.parse_doc(out)
        self.assertEqual(H.differences(jobs, steps, d_jobs, d_steps, said), [])

    def test_a_pipe_in_a_step_name_does_not_split_the_row(self):
        """`|` を含む見出しで表が崩れると、**その行だけ黙って落ちます。**"""
        steps = [('ex.yml', 'build', 'a | b', 10)]
        out = H.apply_doc(DOC, [], steps)
        self.assertEqual(H.parse_doc(out)[1], steps)


class TestBrokenYaml(unittest.TestCase):
    """壊れた木。**「読めない」が「表に無い」に化けないこと。**"""

    def test_an_unreadable_workflow_is_named(self):
        root = tree(workflow='jobs:\n  - [unclosed\n')
        self.assertEqual(H.unreadable(root), ['ex.yml'])

    def test_a_readable_tree_names_nothing(self):
        self.assertEqual(H.unreadable(tree()), [])

    def test_restore_reports_it_instead_of_raising(self):
        root = tree(workflow='jobs:\n  - [unclosed\n')
        problems = H.restore(root, *H.parse_doc(DOC)[:2])
        self.assertTrue(problems)
        self.assertIn('YAML として読めません', problems[0])


class TestTheRealTree(unittest.TestCase):
    """実物。**ここが道具の存在理由です。**"""

    def test_the_shipped_table_reconstructs_the_shipped_tree(self):
        """表 → 木 → 表 が一巡すること。

        木から上限を全部落とし、**文書の表だけ**から入れ直して、
        元の木と中身が一致することを見ます。一致するなら、生成器側は
        表を書き写す必要がありません —— それがこの道具の主張です。
        """
        import shutil
        jobs, steps, missing = H.read_tree(ROOT)
        self.assertEqual(missing, [], '上限の無いジョブが実物にあります')

        root = tempfile.mkdtemp()
        shutil.copytree(os.path.join(ROOT, H.WORKFLOW_DIR),
                        os.path.join(root, H.WORKFLOW_DIR))
        for fn in os.listdir(os.path.join(root, H.WORKFLOW_DIR)):
            path = os.path.join(root, H.WORKFLOW_DIR, fn)
            with open(path, encoding='utf-8') as fh:
                lines = fh.read().split('\n')
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('\n'.join(
                    l for l in lines
                    if l.strip().split(':')[0] != 'timeout-minutes'))
        self.assertEqual(H.read_tree(root)[0], [])

        with open(os.path.join(ROOT, H.HANDOVER), encoding='utf-8') as fh:
            d_jobs, d_steps, _ = H.parse_doc(fh.read())
        self.assertEqual(H.restore(root, d_jobs, d_steps), [])

        back_jobs, back_steps, back_missing = H.read_tree(root)
        self.assertEqual(back_missing, [])
        self.assertEqual(back_jobs, jobs)
        self.assertEqual(back_steps, steps)


if __name__ == '__main__':
    unittest.main(verbosity=2)
