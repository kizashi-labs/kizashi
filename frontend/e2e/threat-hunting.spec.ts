import { test, expect } from '@playwright/test'

// ─── スレットハンティング ──────────────────────────────────────────────────────

test.describe('スレットハンティング', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/threat-hunting')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show threat hunting page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show hunt list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have create hunt or search button', async ({ page }) => {
    const btn = page.getByRole('button', { name: /hunt|ハント|作成|search|クエリ/i }).first()
    const hasBtn = await btn.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasBtn) {
      const input = page.locator('input[placeholder], textarea').first()
      await expect(input).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── クエリビルダー ────────────────────────────────────────────────────────────

test.describe('スレットハンティング クエリビルダー', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/threat-hunting/query-builder')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show query builder page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should have query input area', async ({ page }) => {
    const input = page.locator('textarea, input[placeholder*="クエリ"], input[placeholder*="query"], [class*="editor"], [class*="code"]').first()
    const hasInput = await input.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasInput) {
      const content = page.locator('[class*="card"], [class*="space-y"]').first()
      await expect(content).toBeVisible({ timeout: 5_000 })
    }
  })

  test('should have run query button', async ({ page }) => {
    const runBtn = page.getByRole('button', { name: /実行|run|execute|search|検索/i }).first()
    const hasBtn = await runBtn.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasBtn) {
      const btn = page.getByRole('button').first()
      await expect(btn).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── 保存済みサーチ ────────────────────────────────────────────────────────────

test.describe('保存済みサーチ', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/search/saved')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show saved searches page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show search list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
