import { test, expect } from '@playwright/test'

test.describe('MITRE ATT&CK', () => {
  test('MITREページが表示される', async ({ page }) => {
    await page.goto('/mitre')
    await expect(page.locator('main, [role="main"]')).toBeVisible({ timeout: 10000 })
    await expect(page.getByText(/MITRE|ATT&CK|テクニック/).first()).toBeVisible({ timeout: 10000 })
  })

  test('ヒートマップまたはテクニック一覧が表示される', async ({ page }) => {
    await page.goto('/mitre')
    await page.waitForLoadState('domcontentloaded')
    // テクニックカードや件数表示が存在する
    await expect(
      page.locator('[class*="grid"], table, [class*="card"]').first()
    ).toBeVisible({ timeout: 10000 })
  })

  test('タクティクス列が表示される', async ({ page }) => {
    await page.goto('/mitre')
    await page.waitForLoadState('domcontentloaded')
    // MITRE タクティクスのいずれかが表示される
    await expect(
      page.getByText(/初期アクセス|実行|永続化|権限昇格|防御回避/).first()
    ).toBeVisible({ timeout: 10000 })
  })

  test('サイドバーからMITREページへ遷移できる', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('domcontentloaded')

    // MITRE リンクは「インテリジェンス」ナビグループのサブペイン内にあり、
    // ダッシュボードでは別グループが開いているため、まずグループを展開する。
    const link = page.getByRole('link', { name: /MITRE/i }).first()
    if (!(await link.isVisible({ timeout: 2000 }).catch(() => false))) {
      const groupBtn = page.getByRole('button', { name: 'インテリジェンス' }).first()
      await expect(groupBtn).toBeVisible({ timeout: 5000 })
      await groupBtn.click()
    }

    await expect(link).toBeVisible({ timeout: 5000 })
    await link.click()
    await expect(page).toHaveURL(/\/mitre/, { timeout: 5000 })
  })
})
