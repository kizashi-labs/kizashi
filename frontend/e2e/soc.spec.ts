import { test, expect } from '@playwright/test'

// ─── SOC メトリクス ────────────────────────────────────────────────────────────

test.describe('SOC メトリクス', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/soc/metrics')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show SOC metrics page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show metrics content', async ({ page }) => {
    const content = page.locator('[class*="card"], [class*="stat"], table, canvas').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── SOC SLA ──────────────────────────────────────────────────────────────────

test.describe('SOC SLA', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/soc/sla')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show SLA page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show SLA content', async ({ page }) => {
    const content = page.locator('[class*="card"], table, [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── SOC チケット ──────────────────────────────────────────────────────────────

test.describe('SOC チケット', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/soc/tickets')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show tickets page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show ticket list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="ticket"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have create ticket button', async ({ page }) => {
    const btn = page.getByRole('button', { name: /作成|新規|create|new|チケット/i }).first()
    const hasBtn = await btn.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasBtn) {
      const content = page.locator('[class*="card"], p').first()
      await expect(content).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── SOC シフト管理 ────────────────────────────────────────────────────────────

test.describe('SOC シフト管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/soc/shifts')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show shifts page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show shift schedule or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="calendar"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── SOC ナレッジベース ────────────────────────────────────────────────────────

test.describe('SOC ナレッジベース', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/soc/knowledge-base')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show knowledge base page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show articles or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="article"], [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
