import { test, expect } from '@playwright/test'

// ─── インテグレーション一覧 ────────────────────────────────────────────────────

test.describe('インテグレーション', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/integrations')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show integrations page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show integration cards or list', async ({ page }) => {
    const content = page.locator('[class*="card"], table, [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── Splunk インテグレーション ─────────────────────────────────────────────────

test.describe('Splunk インテグレーション', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/integrations/splunk')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show Splunk integration page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show configuration form', async ({ page }) => {
    const content = page.locator('form, input, [class*="card"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── Elastic インテグレーション ────────────────────────────────────────────────

test.describe('Elastic インテグレーション', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/integrations/elastic')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show Elastic integration page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show configuration form', async ({ page }) => {
    const content = page.locator('form, input, [class*="card"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── LDAP インテグレーション ───────────────────────────────────────────────────

test.describe('LDAP インテグレーション', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/integrations/ldap')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show LDAP integration page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show LDAP config form', async ({ page }) => {
    const content = page.locator('form, input, [class*="card"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── Wazuh インテグレーション ──────────────────────────────────────────────────

test.describe('Wazuh インテグレーション', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/integrations/wazuh')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show Wazuh integration page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show config or status content', async ({ page }) => {
    const content = page.locator('form, input, [class*="card"], [class*="status"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── SOAR インテグレーション ───────────────────────────────────────────────────

test.describe('SOAR インテグレーション', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/integrations/soar')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show SOAR integration page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show config or connection content', async ({ page }) => {
    const content = page.locator('form, input, [class*="card"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
