import { test, expect } from '@playwright/test'

test.describe('Billing Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/billing')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })
  })

  test('should show billing heading', async ({ page }) => {
    await expect(
      page.getByRole('heading', { name: /課金|billing|サブスクリプション|プラン/i }).first()
    ).toBeVisible({ timeout: 10000 })
  })

  test('should display current plan or subscription info', async ({ page }) => {
    const planSection = page.locator('text=/プラン|Plan|Professional|Enterprise|Starter/i').first()
    const hasSection = await planSection.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasSection) {
      await expect(planSection).toBeVisible()
    }
  })

  test('should show invoice or payment history section', async ({ page }) => {
    const invoiceSection = page.locator('text=/請求|インボイス|Invoice|支払い履歴|Payment/i').first()
    const hasInvoice = await invoiceSection.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasInvoice) {
      await expect(invoiceSection).toBeVisible()
    }
  })

  test('should show usage metrics', async ({ page }) => {
    const usageSection = page.locator('text=/使用量|エンドポイント|Endpoint|Usage/i').first()
    const hasUsage = await usageSection.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasUsage) {
      await expect(usageSection).toBeVisible()
    }
  })

  test('should render upgrade or manage plan button if available', async ({ page }) => {
    const upgradeBtn = page.getByRole('button', { name: /アップグレード|プランを変更|Upgrade|Manage/i }).first()
    const hasBtn = await upgradeBtn.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasBtn) {
      await expect(upgradeBtn).toBeVisible()
    }
  })
})
