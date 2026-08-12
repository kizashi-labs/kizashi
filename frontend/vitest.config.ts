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
