import { test, expect } from '@playwright/test'

// ─── フォレンジクス ────────────────────────────────────────────────────────────

test.describe('フォレンジクス', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/forensics')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show forensics page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show forensics content', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── メモリフォレンジクス ──────────────────────────────────────────────────────

test.describe('メモリフォレンジクス', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/forensics/memory')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show memory forensics page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show analysis content or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── タイムライン ──────────────────────────────────────────────────────────────

test.describe('フォレンジクス タイムライン', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/forensics/timeline')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show timeline page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show timeline or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="timeline"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── アーティファクト ──────────────────────────────────────────────────────────

test.describe('フォレンジクス アーティファクト', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/forensics/artifacts')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show artifacts page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show artifact list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
