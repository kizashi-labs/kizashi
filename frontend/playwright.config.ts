import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/global-setup',
  // 290 tests serially on 1 worker took ~1h in CI. Run spec files in parallel
  // (tests within a file stay serial to limit shared-DB-state contention).
  // 2 workers (not 4) reduces CPU contention that caused timing flakiness, and
  // retries=2 absorbs the residual parallel-load flakes so the gate is stable
  // enough to block. Trade-off: ~20min wall-clock (within the 30min job cap).
  fullyParallel: false,
  workers: process.env.CI ? 2 : undefined,
  retries: process.env.CI ? 2 : 0,
  timeout: 30000,
  use: {
    baseURL: process.env.BASE_URL || process.env.E2E_BASE_URL || 'http://localhost:3000',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    storageState: './e2e/.auth/admin.json',
  },
  projects: [
    {
      name: 'setup',
      testMatch: /global-setup\.ts/,
    },
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
      dependencies: ['setup'],
    },
  ],
  reporter: process.env.CI ? [['html'], ['github']] : [['html']],
})
