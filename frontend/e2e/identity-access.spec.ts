import { test, expect } from '@playwright/test'

// ─── アイデンティティ管理 ──────────────────────────────────────────────────────

test.describe('アイデンティティ管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/identity')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show identity page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show identity content', async ({ page }) => {
    const content = page.locator('[class*="card"], table, [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── RBAC ─────────────────────────────────────────────────────────────────────

test.describe('RBAC 管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/rbac')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show RBAC page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show roles or permissions content', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have role management options', async ({ page }) => {
    const role = page.getByText(/admin|analyst|viewer|role|ロール/i).first()
    await expect(role).toBeVisible({ timeout: 8_000 })
  })
})

// ─── SSO 設定 ─────────────────────────────────────────────────────────────────

test.describe('SSO 設定', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/sso')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show SSO page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show SSO configuration form', async ({ page }) => {
    // SSO ページが描画され、設定追加への導線（「…SSO設定を追加」ボタン）が
    // 見えること。フォームはモーダル/別経路で開くため導線の存在を検証する。
    await expect(
      page.getByRole('button', { name: /SSO設定を追加/ }).first(),
    ).toBeVisible({ timeout: 10_000 })
  })
})

// ─── PAM (特権アクセス管理) ────────────────────────────────────────────────────

test.describe('PAM 管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/pam')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show PAM page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show PAM content', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── MFA 管理 ─────────────────────────────────────────────────────────────────

test.describe('MFA 管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/mfa-management')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show MFA management page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show MFA content', async ({ page }) => {
    const content = page.locator('[class*="card"], table, [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
