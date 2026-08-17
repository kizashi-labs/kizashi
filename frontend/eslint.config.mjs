// ESLint 9 のフラット config。
//
// eslint-config-next 16 が eslint >= 9 を要求し、eslint 9 は .eslintrc.json を
// 読まなくなったため、同じ内容をこちらへ移した。
//
// eslint-config-next 16 は `Linter.Config[]` をそのまま export する
// ネイティブのフラット config なので、@eslint/eslintrc の FlatCompat は
// 挟まない。挟むと eslintrc 側のバリデータが next の plugin オブジェクト
// （自己参照を含む）を JSON.stringify しようとして
// "Converting circular structure to JSON" で落ちる。

import nextCoreWebVitals from 'eslint-config-next/core-web-vitals'

const config = [
  {
    // フラット config には .eslintignore が効かないので、無視対象はここに書く。
    ignores: ['.next/**', 'node_modules/**', 'next-env.d.ts', 'coverage/**'],
  },
  ...nextCoreWebVitals,
  {
    rules: {
      // ── 移行前の .eslintrc.json から持ち越し ──────────────────
      'react/no-unescaped-entities': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      'react/no-children-prop': 'warn',

      // ── eslint-plugin-react-hooks v6 で新設されたルール ────────
      //
      // Next 14 の eslint-config-next が使っていた react-hooks v4 には
      // rules-of-hooks（error）と exhaustive-deps（warn）しか無かった。
      // v6 で React Compiler 由来の解析が入り、以下が既定で error になる。
      // このリポジトリの既存コードに対して 149 件出る:
      //
      //   set-state-in-effect          74
      //   purity                       39
      //   static-components            22
      //   refs                          6
      //   immutability                  5
      //   preserve-manual-memoization   3
      //
      // どれもこの差分が持ち込んだものではなく、リンタが新しく見えるように
      // なっただけの既存の指摘。中身も「useEffect の中で setState している」
      // ような、直すのに実際のリファクタリングが要るものが大半で、
      // バージョン移行と同じコミットに混ぜると差分が読めなくなる。
      //
      // 消さずに warn に落として残す。件数が見えていれば別途片付けられるし、
      // ゼロにしてしまうと存在ごと忘れる。CI の `npm run lint` は
      // --max-warnings を渡していないので警告では落ちない。
      //
      // rules-of-hooks は据え置き（現状 0 件、error のまま）。
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/purity': 'warn',
      'react-hooks/static-components': 'warn',
      'react-hooks/refs': 'warn',
      'react-hooks/immutability': 'warn',
      'react-hooks/preserve-manual-memoization': 'warn',
    },
  },
]

export default config
