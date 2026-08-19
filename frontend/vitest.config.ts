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
    // 既定の 5 秒では足りない。tests/lib/ の一群は**ソースツリー全体を走査
    // する検査**（サーバに無い宛先、保存の失敗を握り潰す画面、守られていない
    // 作り物 …）で、1 テストで数十秒かかる。
    //
    // 5 秒のままだと 12 件以上が `Test timed out in 5000ms` になり、**本当の
    // 指摘がその陰に隠れる。** 実際、隠れていた中に「LDAP 統合画面の API が
    // 全部 404 なのに準備中と告知されていない」が含まれていた。
    testTimeout: 120_000,
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
