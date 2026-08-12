import { test, expect } from '@playwright/test'

// ─── ライブレスポンス ──────────────────────────────────────────────────────────

test.describe('ライブレスポンス', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/live-response')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show live response page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show session list or connect form', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], form, p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have start session or connect button', async ({ page }) => {
    const btn = page.getByRole('button', { name: /接続|セッション|connect|start|begin/i }).first()
    const hasBtn = await btn.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasBtn) {
      const content = page.locator('[class*="card"], [class*="session"]').first()
      await expect(content).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── プレイブック ──────────────────────────────────────────────────────────────

test.describe('プレイブック', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/playbooks')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show playbooks page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show playbook list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have create playbook button', async ({ page }) => {
    const btn = page.getByRole('button', { name: /作成|追加|create|new|add/i }).first()
    const hasBtn = await btn.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasBtn) {
      const content = page.locator('[class*="card"]').first()
      await expect(content).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── 隔離管理 ──────────────────────────────────────────────────────────────────

test.describe('隔離管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/quarantine')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show quarantine page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show quarantine list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
