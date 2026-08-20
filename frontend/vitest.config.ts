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
    testTimeout: 180_000,
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
