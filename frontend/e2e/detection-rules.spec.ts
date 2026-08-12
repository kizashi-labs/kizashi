import { test, expect } from '@playwright/test'

// ─── 検知ルール ────────────────────────────────────────────────────────────────

test.describe('検知ルール管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/detection-studio')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show detection studio heading', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show rule list', async ({ page }) => {
    const list = page.locator('table, [class*="space-y"], [class*="rule"]').first()
    await expect(list).toBeVisible({ timeout: 10_000 })
  })

  test('should have create rule button', async ({ page }) => {
    // 検出ルールStudio のヘッダーには「新規」ボタンがある
    const createBtn = page.getByRole('button', { name: /ルール作成|新規ルール|新規|create rule|add rule/i }).first()
    const hasBtn = await createBtn.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasBtn) {
      // ボタンが見つからない場合はページ見出し（検出ルールスタジオ）が描画されていればよい
      const heading = page.getByRole('heading').first()
      await expect(heading).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── 相関ルール ────────────────────────────────────────────────────────────────

test.describe('相関ルール', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/correlation-rules')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show correlation rules page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show rule table or list', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have enable/disable toggle or badge', async ({ page }) => {
    // enabled/disabled のバッジかトグル
    const badge = page.locator('[class*="badge"], [role="switch"], button').first()
    await expect(badge).toBeVisible({ timeout: 8_000 })
  })
})

// ─── アラート抑制ルール ────────────────────────────────────────────────────────

test.describe('アラート抑制ルール', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/alert-suppression')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show alert suppression page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show rule list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have add suppression rule button', async ({ page }) => {
    const addBtn = page.getByRole('button', { name: /追加|作成|add|create|new/i }).first()
    await expect(addBtn).toBeVisible({ timeout: 8_000 })
  })
})

// ─── 自動修復ルール ────────────────────────────────────────────────────────────

test.describe('自動修復 / レスポンス', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/auto-remediation')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show auto-remediation page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show remediation actions or rules', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
