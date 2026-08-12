import { test, expect } from '@playwright/test'

// ─── ネットワーク監視 ──────────────────────────────────────────────────────────

test.describe('ネットワーク監視', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/network')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show network page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show network content', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"], canvas, svg').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── ネットワークトポロジー ────────────────────────────────────────────────────

test.describe('ネットワークトポロジー', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/network-topology')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show network topology page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show topology graph or empty state', async ({ page }) => {
    const content = page.locator('canvas, svg, [class*="topology"], [class*="graph"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── ネットワーク接続 ──────────────────────────────────────────────────────────

test.describe('ネットワーク接続', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/network-connections')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show network connections page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show connection table or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── DNS セキュリティ ──────────────────────────────────────────────────────────

test.describe('DNS セキュリティ', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/dns-security')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show DNS security page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show DNS content', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
