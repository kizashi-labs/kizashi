import { test, expect } from '@playwright/test'

// ─── コンプライアンス ──────────────────────────────────────────────────────────

test.describe('コンプライアンス', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/compliance')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show compliance page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show compliance content', async ({ page }) => {
    const content = page.locator('[class*="card"], table, [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should show compliance score or status', async ({ page }) => {
    const score = page.locator('[class*="score"], [class*="stat"], [class*="percent"], [class*="badge"]').first()
    const hasScore = await score.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasScore) {
      const text = page.locator('text=/\\d+/').first()
      await expect(text).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── コンプライアンスカレンダー ────────────────────────────────────────────────

test.describe('コンプライアンスカレンダー', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/compliance/calendar')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show calendar page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show calendar or schedule content', async ({ page }) => {
    const content = page.locator('[class*="calendar"], table, [class*="card"], [class*="schedule"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── コンプライアンスワークフロー ─────────────────────────────────────────────

test.describe('コンプライアンスワークフロー', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/compliance-workflows')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show workflows page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show workflow list or content', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── コンプライアンスエビデンス ────────────────────────────────────────────────

test.describe('コンプライアンスエビデンス', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/compliance-evidence')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show compliance evidence page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show evidence content', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
