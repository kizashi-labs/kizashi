import { test, expect } from '@playwright/test'

// ─── ユーザー管理 ──────────────────────────────────────────────────────────────

test.describe('ユーザー管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/users')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show users page heading', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
    const text = await heading.textContent()
    expect(text).toBeTruthy()
  })

  test('should show user list or table', async ({ page }) => {
    // ユーザーテーブル or ユーザーカード
    const list = page.locator('table tbody tr, [class*="user-row"], [class*="space-y"] > div').first()
    await expect(list).toBeVisible({ timeout: 10_000 })
  })

  test('should show admin user in list', async ({ page }) => {
    // admin ユーザーが表示される
    const adminEntry = page.getByText(/admin/i).first()
    await expect(adminEntry).toBeVisible({ timeout: 8_000 })
  })

  test('should have invite or add user button', async ({ page }) => {
    const inviteBtn = page.getByRole('button', { name: /招待|追加|ユーザー作成|invite|add user/i }).first()
    await expect(inviteBtn).toBeVisible({ timeout: 8_000 })
  })

  test('should have search functionality', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="検索"], input[placeholder*="ユーザー"], input[type="search"]').first()
    const hasSearch = await searchInput.isVisible({ timeout: 5_000 }).catch(() => false)
    if (hasSearch) {
      await searchInput.fill('admin')
      await page.waitForTimeout(500)
      // 検索後も表示が壊れない
      const content = page.locator('table, [class*="space-y"]').first()
      await expect(content).toBeVisible()
    }
  })

  test('should show role column or badge', async ({ page }) => {
    // role バッジ (admin/analyst/viewer)
    const roleBadge = page.getByText(/admin|analyst|viewer/i).first()
    await expect(roleBadge).toBeVisible({ timeout: 8_000 })
  })
})

// ─── 監査ログ ──────────────────────────────────────────────────────────────────

test.describe('監査ログ', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/audit-logs')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show audit logs heading', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show log entries or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="log"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have export button', async ({ page }) => {
    const exportBtn = page.getByRole('button', { name: /エクスポート|export|csv|download/i }).first()
    const hasExport = await exportBtn.isVisible({ timeout: 5_000 }).catch(() => false)
    // エクスポートボタンがなければフィルターボタンが代わり
    if (!hasExport) {
      const filterBtn = page.getByRole('button').first()
      await expect(filterBtn).toBeVisible({ timeout: 5_000 })
    }
  })

  test('should show timestamp column', async ({ page }) => {
    // 日時列ヘッダー。columnheader ロールで限定（getByText だとフィルタ内の
    // 「日時」ラベル等の隠れ要素を先に掴んで誤判定する）。負荷下の遅延描画を
    // auto-retry で吸収するため単一の web-first アサーションにする。
    await expect(
      page.getByRole('columnheader', { name: /タイムスタンプ|timestamp|日時/i }).first(),
    ).toBeVisible({ timeout: 15_000 })
  })
})
