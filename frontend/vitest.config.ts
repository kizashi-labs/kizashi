import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./tests/setup.ts'],
    // Playwright specs in e2e/** share the *.spec.ts extension that vitest
    // also auto-discovers, but they call `test.describe` from @playwright/test
    // which throws outside Playwright's runner. Without this exclude, 38 e2e
    // files show up as "0 test FAIL" and mask real vitest failures in output.
    exclude: ['**/node_modules/**', '**/dist/**', '**/.next/**', 'e2e/**'],
    // tests/lib/ の走査系は app/** と components/** を丸ごと読んで正規表現を
    // かけるので、1件で数十秒かかる（実測で 109 秒のものがある）。既定の
    // 5 秒のままだと、**同じ木・同じコードのまま、走らせた機械の速さだけで
    // 赤くなる。** 遅いだけの回と、本当に壊れている回が同じ形（Test timed out）
    // で出るので、走査が終わるだけの時間を渡しておく。
    //
    // 180 秒 → 600 秒（2026-08-21）。**同じ木で実測した**:
    //
    //	Linux (CI と同じ)     25 ファイル / 453 件 = 262 秒
    //	Windows (生成器)      同じもの        = 1145 秒、うち 11 件が 180 秒で時間切れ
    //
    // 生成器は Windows で回っていて、そこで `recalibrate_ratchets.py` が
    // この走査を実測に使います。**時間切れは「下げられる指摘」を 1 つも
    // 出さない**ので、呼び出し側（make-snapshot.sh 3.55）は
    // 「ラチェットに上がる方向のずれ」と読みます —— 機械の速さを木の劣化と
    // 取り違えます。上限は、いちばん遅い機械が終われる幅に置きます。
    //
    // **速くする話は別です。** Windows で 4 倍かかるのは 3000 ファイルを
    // 各テストが読み直すからで、Defender の除外を入れるほうがよく効きます。
    testTimeout: 1_800_000,
    coverage: {
      reporter: ['text', 'lcov'],
      include: ['components/**', 'lib/**', 'hooks/**'],
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },
})
