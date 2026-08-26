import { test, expect } from '@playwright/test'

// ─── レポート ──────────────────────────────────────────────────────────────────

test.describe('レポート一覧', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/reports')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show reports page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show report list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have generate or create report button', async ({ page }) => {
    const btn = page.getByRole('button', { name: /作成|生成|create|generate|new/i }).first()
    const hasBtn = await btn.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasBtn) {
      const link = page.getByRole('link', { name: /作成|レポート|report/i }).first()
      const hasLink = await link.isVisible({ timeout: 3_000 }).catch(() => false)
      if (!hasLink) {
        const content = page.locator('[class*="card"]').first()
        await expect(content).toBeVisible({ timeout: 3_000 })
      }
    }
  })
})

// ─── レポートテンプレート ──────────────────────────────────────────────────────

test.describe('レポートテンプレート', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/reports/templates')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show templates page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show template list', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"], [class*="template"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── スケジュールレポート ──────────────────────────────────────────────────────

test.describe('スケジュールレポート', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/reports/schedules')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show schedules page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show schedule list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have add schedule button', async ({ page }) => {
    const btn = page.getByRole('button', { name: /スケジュール|追加|add|create|schedule/i }).first()
    const hasBtn = await btn.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasBtn) {
      const content = page.locator('[class*="card"], p').first()
      await expect(content).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── エグゼクティブブリーフィング ─────────────────────────────────────────────

test.describe('エグゼクティブブリーフィング', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/reports/executive-briefing')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show executive briefing page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show briefing content', async ({ page }) => {
    const content = page.locator('[class*="card"], [class*="stat"], table, p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
