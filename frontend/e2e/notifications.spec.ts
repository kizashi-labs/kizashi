import { test, expect } from '@playwright/test'

test.describe('通知チャンネル管理', () => {
  test('通知設定ページが表示される', async ({ page }) => {
    await page.goto('/notifications')
    await expect(page.getByText('通知設定').first()).toBeVisible({ timeout: 10000 })
  })

  test('チャンネル設定タブが表示される', async ({ page }) => {
    await page.goto('/notifications')
    await expect(page.getByText('チャンネル設定')).toBeVisible({ timeout: 5000 })
    await expect(page.getByText('送信履歴')).toBeVisible({ timeout: 5000 })
  })

  test('チャンネルを追加ボタンが表示される', async ({ page }) => {
    await page.goto('/notifications')
    await expect(page.getByText('チャンネルを追加')).toBeVisible({ timeout: 5000 })
  })

  test('チャンネル追加フォームが開閉できる', async ({ page }) => {
    await page.goto('/notifications')
    await page.getByText('チャンネルを追加').click()
    await expect(page.getByText('新しい通知チャンネル')).toBeVisible({ timeout: 3000 })
    await page.getByText('キャンセル').click()
    await expect(page.getByText('新しい通知チャンネル')).not.toBeVisible({ timeout: 3000 })
  })

  test('チャンネル種類の選択肢が正しい', async ({ page }) => {
    await page.goto('/notifications')
    await page.getByText('チャンネルを追加').click()
    const select = page.locator('select').first()
    await expect(select).toBeVisible({ timeout: 3000 })
    const options = await select.locator('option').allTextContents()
    expect(options.some(o => o.includes('Slack'))).toBeTruthy()
    expect(options.some(o => o.includes('メール') || o.includes('email'))).toBeTruthy()
    expect(options.some(o => o.includes('Webhook'))).toBeTruthy()
    expect(options.some(o => o.includes('Teams'))).toBeTruthy()
  })

  test('送信履歴タブに切り替えられる', async ({ page }) => {
    await page.goto('/notifications')
    await page.getByText('送信履歴').click()
    // 統計カードまたは「履歴なし」が表示される
    await expect(
      page.getByText(/7日間|送信成功|送信失敗|送信履歴はありません/).first()
    ).toBeVisible({ timeout: 5000 })
  })

  test('設定ページからリンクで遷移できる', async ({ page }) => {
    await page.goto('/settings')
    await page.waitForLoadState('domcontentloaded')
    const link = page.getByText('通知チャンネルを管理する')
    // 設定ページは長いのでスクロールして表示させる
    await link.scrollIntoViewIfNeeded()
    await expect(link).toBeVisible({ timeout: 10000 })
    await link.click()
    await expect(page).toHaveURL(/\/notifications/, { timeout: 5000 })
  })
})
