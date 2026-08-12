import { test, expect } from '@playwright/test'

test.describe('エンドポイント管理', () => {
  test('エンドポイント一覧ページが表示される', async ({ page }) => {
    await page.goto('/endpoints')
    await expect(page.locator('main, [role="main"]')).toBeVisible({ timeout: 10000 })
    // ホスト名・OS など何らかのテーブルヘッダーか、エンドポイントなしメッセージ
    await expect(
      page.getByText(/エンドポイント|ホスト名|エージェント/).first()
    ).toBeVisible({ timeout: 5000 })
  })

  test('検索フィールドが存在する', async ({ page }) => {
    await page.goto('/endpoints')
    const searchInput = page.locator('input[placeholder*="検索"], input[type="search"]').first()
    await expect(searchInput).toBeVisible({ timeout: 5000 })
  })
})
