import { test, expect } from '@playwright/test'

test.describe('Performance dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/performance')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })
  })

  test('should show page heading', async ({ page }) => {
    await expect(
      page.getByRole('heading', { name: /パフォーマンス|Performance/i }).first()
    ).toBeVisible({ timeout: 10000 })
  })

  test('should show Core Web Vitals metric cards', async ({ page }) => {
    // Each vital should have a named card
    for (const vital of ['LCP', 'FCP', 'CLS', 'INP', 'TTFB']) {
      await expect(
        page.getByText(vital).first()
      ).toBeVisible({ timeout: 8000 })
    }
  })

  test('should show overall score section', async ({ page }) => {
    // Overall score card or "サマリー" section
    const scoreSection = page.locator(
      '[class*="rounded"], [class*="card"]'
    ).filter({ hasText: /スコア|Score|サマリー|Vitals/i }).first()
    await expect(scoreSection).toBeVisible({ timeout: 8000 })
  })

  test('should show refresh button', async ({ page }) => {
    const refreshBtn = page.getByRole('button', { name: /更新|Refresh/i }).first()
    await expect(refreshBtn).toBeVisible({ timeout: 8000 })
    // Clicking refresh should not throw
    await refreshBtn.click()
  })

  test('should show clear button', async ({ page }) => {
    const clearBtn = page.getByRole('button', { name: /クリア|Clear/i }).first()
    await expect(clearBtn).toBeVisible({ timeout: 8000 })
  })

  test('should show Google Core Web Vitals reference table', async ({ page }) => {
    const table = page.locator('table').first()
    await expect(table).toBeVisible({ timeout: 8000 })
  })
})
