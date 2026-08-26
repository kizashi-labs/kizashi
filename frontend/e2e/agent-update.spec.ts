import { test, expect } from '@playwright/test'

test.describe('Agent Auto-Update page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/agent-update')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })
  })

  test('should show page heading', async ({ page }) => {
    // Page renders heading in Japanese: "エージェント自動更新"
    await expect(
      page.getByRole('heading', { name: /Agent Auto-Update|自動更新|自動アップデート/i }).first()
    ).toBeVisible({ timeout: 10000 })
  })

  test('should show rollout progress card', async ({ page }) => {
    // Rollout progress card heading is "ロールアウト進捗"
    const rolloutCard = page.locator('[class*="rounded"]')
      .filter({ hasText: /Rollout Progress|ロールアウト進捗/i })
      .first()
    await expect(rolloutCard).toBeVisible({ timeout: 8000 })
  })

  test('should show rollout KPI stats', async ({ page }) => {
    // KPI labels are rendered in Japanese: 目標バージョン / 完了率
    await expect(page.getByText(/On Target|目標バージョン/i).first()).toBeVisible({ timeout: 8000 })
    await expect(page.getByText(/Completion|完了率/i).first()).toBeVisible({ timeout: 8000 })
  })

  test('should show update policy section', async ({ page }) => {
    // Section heading is "更新ポリシー"
    await expect(
      page.getByText(/Update Policy|更新ポリシー/i).first()
    ).toBeVisible({ timeout: 8000 })
  })

  test('should show auto-update toggle', async ({ page }) => {
    const toggle = page.locator('button[class*="rounded-full"]').first()
    await expect(toggle).toBeVisible({ timeout: 8000 })
  })

  test('should show rollout percentage slider', async ({ page }) => {
    const slider = page.locator('input[type="range"]').first()
    await expect(slider).toBeVisible({ timeout: 8000 })
  })

  test('should show available versions table', async ({ page }) => {
    // Section heading is "利用可能なバージョン"; the <table> element renders even
    // when the DB has no version rows (only rows are data-dependent).
    await expect(
      page.getByText(/Available Versions|利用可能なバージョン/i).first()
    ).toBeVisible({ timeout: 8000 })
    const table = page.locator('table').first()
    await expect(table).toBeVisible({ timeout: 8000 })
  })

  test('should show pending updates section', async ({ page }) => {
    // Section heading is "更新待ちエージェント"
    await expect(
      page.getByText(/Pending Updates|更新待ち/i).first()
    ).toBeVisible({ timeout: 8000 })
  })

  test('should show manual update section', async ({ page }) => {
    // Section heading is "手動更新"
    await expect(
      page.getByText(/Manual Update|手動更新/i).first()
    ).toBeVisible({ timeout: 8000 })
  })

  test('should show bulk update platform buttons', async ({ page }) => {
    // Bulk-update section ("プラットフォーム別に全エージェントを更新") renders one
    // button per platform (windows/linux/macos), all labelled
    // "プラットフォーム全エージェント更新". Assert the section + 3 buttons exist.
    await expect(
      page.getByText(/プラットフォーム別に全エージェントを更新/i).first()
    ).toBeVisible({ timeout: 8000 })
    const bulkBtns = page.getByRole('button', { name: /Update All|プラットフォーム全エージェント更新/i })
    await expect(bulkBtns).toHaveCount(3, { timeout: 8000 })
  })

  test('should show save policy button', async ({ page }) => {
    // Button text is "ポリシーを保存"
    const saveBtn = page.getByRole('button', { name: /Save Policy|ポリシーを保存/i }).first()
    await expect(saveBtn).toBeVisible({ timeout: 8000 })
  })

  test('should show refresh button in header', async ({ page }) => {
    // Header refresh button text is "更新"
    const refreshBtn = page.getByRole('button', { name: /^Refresh$|^更新$/i }).first()
    await expect(refreshBtn).toBeVisible({ timeout: 8000 })
    await refreshBtn.click()
    // After click, page should still be functional
    await expect(page.locator('h1').first()).toBeVisible({ timeout: 5000 })
  })
})
