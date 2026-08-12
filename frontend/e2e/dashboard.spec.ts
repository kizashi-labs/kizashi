import { test, expect } from '@playwright/test'

// ─── Dashboard ────────────────────────────────────────────────────────────────
// Authentication is provided by the shared storageState (see global-setup.ts).
// No per-test login — calling the login helper would overwrite the valid
// seeded-admin token with an invalid fallback token and break protected routes.

test.describe('Dashboard', () => {
  /**
   * 1. Main dashboard loads without errors
   */
  test('main dashboard loads without errors', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // Primary heading "ダッシュボード"
    await expect(
      page.getByRole('heading', { name: 'ダッシュボード' }).first(),
    ).toBeVisible({ timeout: 10000 })

    // No uncaught-error overlay (Next.js shows one in development)
    const errorOverlay = page.locator('#nextjs-portal, [data-nextjs-dialog]')
    const hasError = await errorOverlay.isVisible().catch(() => false)
    expect(hasError).toBe(false)
  })

  /**
   * 2. Key stat cards are visible
   * The quick-stats widget renders three KPI cards (未対応アラート / エージェント /
   * オープンインシデント) linking to the relevant pages. Data may be empty in CI,
   * but the cards and their links must still render.
   */
  test('key stat cards are visible', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // KPI card labels
    await expect(page.getByText('未対応アラート').first()).toBeVisible({ timeout: 10000 })
    await expect(page.getByText('オープンインシデント').first()).toBeVisible({ timeout: 10000 })

    // Stat card linking to the endpoints page must be present and show a value
    const endpointsCard = page.locator('a[href="/endpoints"]').first()
    await expect(endpointsCard).toBeVisible({ timeout: 10000 })
    const cardText = await endpointsCard.textContent()
    // Card shows an "online/total" figure — should contain at least one digit
    expect(cardText).toMatch(/\d/)
  })

  /**
   * 3. Navigation links work
   * Clicks the sidebar alerts link from the dashboard and confirms navigation
   * to /alerts. Then verifies the alerts page heading is present.
   */
  test('navigation links work', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // Sidebar link "アラート"
    const alertsLink = page.getByRole('link', { name: /アラート/ }).first()
    await expect(alertsLink).toBeVisible({ timeout: 8000 })
    await alertsLink.click()

    await expect(page).toHaveURL(/\/alerts/, { timeout: 10000 })
    await expect(
      page.getByRole('heading', { name: /アラート/ }).first(),
    ).toBeVisible({ timeout: 10000 })
  })

  /**
   * 4. Dashboard renders its widget surface (header + at least one widget card)
   * The dashboard has no global "system status" banner; instead it surfaces a
   * widget grid. Verify the header and a representative widget are present.
   */
  test('dashboard widget surface is visible', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // Header subtitle is always rendered
    await expect(page.getByText('セキュリティ概況').first()).toBeVisible({ timeout: 10000 })

    // The "AI Insight" widget renders a live indicator regardless of data
    const liveIndicator = page.getByText(/AI Security Insight|Live/i).first()
    await expect(liveIndicator).toBeVisible({ timeout: 10000 })
  })
})
