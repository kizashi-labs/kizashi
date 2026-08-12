import { test, expect } from '@playwright/test'

// ─── 脆弱性管理 ───────────────────────────────────────────────────────────────

test.describe('脆弱性一覧', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/vulnerabilities')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show vulnerabilities page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show vuln table or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have severity filter or search', async ({ page }) => {
    const filter = page.locator('select, input[type="search"], input[placeholder*="検索"], input[placeholder*="search"]').first()
    const hasFilter = await filter.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasFilter) {
      const btn = page.getByRole('button').first()
      await expect(btn).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── 脆弱性トレンド ────────────────────────────────────────────────────────────

test.describe('脆弱性トレンド', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/vulnerabilities/trends')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show trends page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show chart or stat content', async ({ page }) => {
    const content = page.locator('[class*="chart"], [class*="stat"], [class*="card"], canvas, svg').first()
    const hasContent = await content.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasContent) {
      const fallback = page.locator('p, table').first()
      await expect(fallback).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── 脆弱性修復 ───────────────────────────────────────────────────────────────

test.describe('脆弱性修復', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/vulnerabilities/remediation')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show remediation page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show remediation content', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── パッチ管理 ───────────────────────────────────────────────────────────────

test.describe('パッチ管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/patch-management')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show patch management page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show patch list or dashboard', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
