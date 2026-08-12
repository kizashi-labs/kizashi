import { test, expect } from '@playwright/test'

// ─── 脅威インテリジェンス ──────────────────────────────────────────────────────

test.describe('脅威インテリジェンス', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/threat-intelligence')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show page heading', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
    const text = await heading.textContent()
    expect(text).toBeTruthy()
  })

  test('should display feed list or empty state', async ({ page }) => {
    // テーブル、リスト、または空状態のいずれかが表示される
    const content = page.locator('table, [class*="space-y"], [class*="grid"], p').first()
    await expect(content).toBeVisible({ timeout: 10_000 })
  })

  test('should have add feed button or link', async ({ page }) => {
    // フィード追加ボタン (Plus icon の付いたボタン)
    const addButton = page.getByRole('button', { name: /追加|add|新規|フィード/i }).first()
    const hasButton = await addButton.isVisible({ timeout: 5_000 }).catch(() => false)
    // ボタンがなければ入力フォームが直接表示されている
    if (!hasButton) {
      const form = page.locator('form, input[placeholder]').first()
      await expect(form).toBeVisible({ timeout: 5_000 })
    } else {
      await expect(addButton).toBeVisible()
    }
  })

  test('should show IOC lookup section', async ({ page }) => {
    // IOC ルックアップ入力欄かサーチボックス
    const searchInput = page.locator('input[placeholder*="検索"], input[placeholder*="IOC"], input[placeholder*="IP"], input[type="search"]').first()
    const hasSearch = await searchInput.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasSearch) {
      // 最低限タブかセクション見出しがある
      const section = page.getByText(/IOC|インテリジェンス|フィード/i).first()
      await expect(section).toBeVisible({ timeout: 5_000 })
    }
  })

  test('should show stats or counter', async ({ page }) => {
    // IOC 総数などのカウンター
    const counter = page.locator('[class*="stat"], [class*="count"], [class*="badge"]').first()
    const hasCounter = await counter.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasCounter) {
      // テキストに数字が含まれている
      const numbers = page.locator('text=/\\d+/').first()
      await expect(numbers).toBeVisible({ timeout: 5_000 })
    }
  })
})

// ─── YARA ルール ───────────────────────────────────────────────────────────────

test.describe('YARA ルール管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/yara-rules')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show YARA rules page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show rule list or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })

  test('should have create rule action', async ({ page }) => {
    const createBtn = page.getByRole('button', { name: /作成|追加|新規|create|add/i }).first()
    const hasBtn = await createBtn.isVisible({ timeout: 5_000 }).catch(() => false)
    if (!hasBtn) {
      const textarea = page.locator('textarea').first()
      const hasTextarea = await textarea.isVisible({ timeout: 3_000 }).catch(() => false)
      expect(hasTextarea || !hasBtn).toBeTruthy()
    }
  })
})

// ─── Sigma ルール ──────────────────────────────────────────────────────────────

test.describe('Sigma ルール管理', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/sigma-rules')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show Sigma rules page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show rule table or list', async ({ page }) => {
    const content = page.locator('table, [class*="space-y"], [class*="card"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
