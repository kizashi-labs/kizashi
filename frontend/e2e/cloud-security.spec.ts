import { test, expect } from '@playwright/test'

// ─── クラウドセキュリティ ──────────────────────────────────────────────────────

test.describe('クラウドセキュリティ', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/cloud-security')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show cloud security page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show cloud security content', async ({ page }) => {
    const content = page.locator('[class*="card"], table, [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── クラウドアセット ──────────────────────────────────────────────────────────

test.describe('クラウドアセット', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/cloud-assets')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show cloud assets page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show asset list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── コンテナセキュリティ ──────────────────────────────────────────────────────

test.describe('コンテナセキュリティ', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/container-security')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show container security page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show container list or content', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── クラウド SIEM ─────────────────────────────────────────────────────────────

test.describe('クラウド SIEM', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/cloud-siem')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show cloud SIEM page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show SIEM content', async ({ page }) => {
    const content = page.locator('[class*="card"], table, [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── ゼロトラスト ──────────────────────────────────────────────────────────────

test.describe('ゼロトラスト', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/zero-trust')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show zero trust page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show zero trust content', async ({ page }) => {
    const content = page.locator('[class*="card"], table, [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
