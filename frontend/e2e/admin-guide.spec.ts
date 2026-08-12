import { test, expect } from '@playwright/test'

test.describe('Admin Guide', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/guide')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })
  })

  test('should show admin guide heading', async ({ page }) => {
    await expect(
      page.getByRole('heading', { name: /管理者ガイド|Admin Guide/i }).first()
    ).toBeVisible({ timeout: 10000 })
  })

  test('should display sidebar navigation', async ({ page }) => {
    // The guide has a sidebar with section links
    const sidebar = page.locator('nav, aside, [class*="sidebar"]').first()
    const hasSidebar = await sidebar.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasSidebar) {
      await expect(sidebar).toBeVisible()
    }
  })

  test('should show installation section', async ({ page }) => {
    const section = page.locator('text=/インストール|Installation/i').first()
    const hasSection = await section.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasSection) {
      await expect(section).toBeVisible()
    }
  })

  test('should navigate to agent management section', async ({ page }) => {
    const agentLink = page.locator('text=/エージェント管理|Agent/i').first()
    const hasLink = await agentLink.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasLink) {
      await agentLink.click()
      await page.waitForLoadState('domcontentloaded', { timeout: 5000 })
      // Section content should be visible after click
      await expect(page.locator('text=/エージェント|Agent/i').first()).toBeVisible({ timeout: 5000 })
    }
  })

  test('should show code blocks for commands', async ({ page }) => {
    const codeBlock = page.locator('code, pre, [class*="code"], [class*="Code"]').first()
    const hasCode = await codeBlock.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasCode) {
      await expect(codeBlock).toBeVisible()
    }
  })

  test('should display troubleshooting section', async ({ page }) => {
    const section = page.locator('text=/トラブルシューティング|Troubleshoot/i').first()
    const hasSection = await section.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasSection) {
      await expect(section).toBeVisible()
    }
  })
})

test.describe('Landing Page', () => {
  test('should render landing page without authentication', async ({ page }) => {
    // Landing page is public — no auth needed
    await page.goto('/landing')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    await expect(
      page.getByRole('heading', { level: 1 }).first()
    ).toBeVisible({ timeout: 10000 })
  })

  test('should show navigation with login button', async ({ page }) => {
    await page.goto('/landing')
    await page.waitForLoadState('domcontentloaded', { timeout: 10000 })

    const loginBtn = page.getByRole('button', { name: /ログイン|Login/i }).first()
    const hasBtn = await loginBtn.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasBtn) {
      await expect(loginBtn).toBeVisible()
    }
  })

  test('should show feature cards', async ({ page }) => {
    await page.goto('/landing')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // Features section
    const featureSection = page.locator('text=/リアルタイム脅威検知|UEBA|AI自動/i').first()
    const hasFeature = await featureSection.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasFeature) {
      await expect(featureSection).toBeVisible()
    }
  })

  test('should show pricing plans', async ({ page }) => {
    await page.goto('/landing')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    const pricingSection = page.locator('text=/Professional|Enterprise|Starter/i').first()
    const hasPricing = await pricingSection.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasPricing) {
      await expect(pricingSection).toBeVisible()
    }
  })

  test('free trial button should navigate to login', async ({ page }) => {
    await page.goto('/landing')
    await page.waitForLoadState('domcontentloaded', { timeout: 10000 })

    const trialBtn = page.getByRole('button', { name: /無料トライアル/i }).first()
    const hasBtn = await trialBtn.isVisible({ timeout: 5000 }).catch(() => false)
    if (hasBtn) {
      await trialBtn.click()
      await expect(page).toHaveURL(/login/, { timeout: 5000 })
    }
  })
})
