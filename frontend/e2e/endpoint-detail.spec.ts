import { test, expect } from '@playwright/test'

test.describe('エンドポイント詳細・フォレンジックタイムライン', () => {
  test('エンドポイント一覧からホスト名リンクが存在する', async ({ page }) => {
    await page.goto('/endpoints')
    await page.waitForLoadState('domcontentloaded')
    // エンドポイントが0件の場合はスキップ
    const rows = page.locator('table tbody tr')
    const count = await rows.count()
    if (count === 0) {
      test.skip()
      return
    }
    const firstLink = page.locator('table tbody tr').first().locator('a').first()
    await expect(firstLink).toBeVisible({ timeout: 5000 })
  })

  test('エンドポイント詳細ページが表示される', async ({ page }) => {
    // エンドポイント一覧からIDを取得してアクセス
    await page.goto('/endpoints')
    await page.waitForLoadState('domcontentloaded')
    const firstLink = page.locator('table tbody tr a').first()
    const count = await firstLink.count()
    if (count === 0) {
      test.skip()
      return
    }
    await firstLink.click()
    // 詳細ページのタブが表示されること
    await expect(page.getByText(/概要|overview/i).first()).toBeVisible({ timeout: 10000 })
  })

  test('エンドポイント詳細のタイムラインタブが存在する', async ({ page }) => {
    await page.goto('/endpoints')
    await page.waitForLoadState('domcontentloaded')
    const firstLink = page.locator('table tbody tr a').first()
    if (await firstLink.count() === 0) {
      test.skip()
      return
    }
    await firstLink.click()
    await expect(page.getByText('タイムライン')).toBeVisible({ timeout: 10000 })
  })

  test('タイムラインタブに切り替えると時間フィルタが表示される', async ({ page }) => {
    await page.goto('/endpoints')
    await page.waitForLoadState('domcontentloaded')
    const firstLink = page.locator('table tbody tr a').first()
    if (await firstLink.count() === 0) {
      test.skip()
      return
    }
    await firstLink.click()
    await page.getByText('タイムライン').click()
    // 時間フィルタボタン（1h, 4h, 12h, 24h など）
    await expect(page.getByText(/1h|4h|12h|24h/)).toBeVisible({ timeout: 5000 })
    // カテゴリフィルタ
    await expect(page.getByText(/alert|process|network|file/i).first()).toBeVisible({ timeout: 5000 })
  })

  test('タイムライン：時間範囲の切り替えができる', async ({ page }) => {
    await page.goto('/endpoints')
    await page.waitForLoadState('domcontentloaded')
    const firstLink = page.locator('table tbody tr a').first()
    if (await firstLink.count() === 0) {
      test.skip()
      return
    }
    await firstLink.click()
    await page.getByText('タイムライン').click()
    // 72h (3d) ボタンをクリック
    const btn72 = page.getByText('3d')
    if (await btn72.count() > 0) {
      await btn72.click()
      // ボタンがアクティブ（青）になる
      await expect(btn72).toHaveClass(/bg-\[#1a6bff\]/, { timeout: 3000 })
    }
  })
})
