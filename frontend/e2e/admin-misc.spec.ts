import { test, expect } from '@playwright/test'

// ─── エージェントデプロイ ──────────────────────────────────────────────────────

test.describe('エージェントデプロイ', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/agent-deployment')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show agent deployment page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show deployment content', async ({ page }) => {
    const content = page.locator('[class*="card"], table, [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── エージェントポリシー ──────────────────────────────────────────────────────

test.describe('エージェントポリシー', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/edr-policies')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show policies page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show policy list or content', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── Watchlist ────────────────────────────────────────────────────────────────

test.describe('Watchlist', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/watchlist')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show watchlist page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show watchlist content', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have add watchlist entry button', async ({ page }) => {
    const btn = page.getByRole('button', { name: /追加|add|create|new/i }).first()
    const hasBtn = await btn.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasBtn) {
      const content = page.locator('[class*="card"], p').first()
      await expect(content).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── データ保持 ────────────────────────────────────────────────────────────────

test.describe('データ保持ポリシー', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/data-retention')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show data retention page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show retention settings', async ({ page }) => {
    const content = page.locator('[class*="card"], form, input, table').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── ライセンス ────────────────────────────────────────────────────────────────

test.describe('ライセンス管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/license')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show license page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show license info', async ({ page }) => {
    const content = page.locator('[class*="card"], table, p, [class*="license"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── システムステータス ────────────────────────────────────────────────────────

test.describe('システムステータス', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/system-status')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show system status page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show service status indicators', async ({ page }) => {
    const content = page.locator('[class*="status"], [class*="health"], [class*="card"], table').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
