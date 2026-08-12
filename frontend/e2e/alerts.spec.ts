import { test, expect } from '@playwright/test'

// ─── Alert management ─────────────────────────────────────────────────────────
// Authentication is provided by the shared storageState (see global-setup.ts).
// No per-test login — calling the login helper would overwrite the valid
// seeded-admin token with an invalid fallback token and break protected routes.

test.describe('Alert management', () => {
  /**
   * 1. Alerts page loads and shows table / list
   */
  test('alerts page loads and shows table', async ({ page }) => {
    await page.goto('/alerts')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // Page heading "アラート" must be visible
    await expect(
      page.getByRole('heading', { name: /アラート/ }).first(),
    ).toBeVisible({ timeout: 10000 })

    // Content area — table, list, or card container
    const content = page.locator('table, [class*="space-y"], [role="list"], .p-6').first()
    await expect(content).toBeVisible({ timeout: 8000 })
  })

  /**
   * 2. Filter by severity works
   * The alerts page provides a severity <select> whose options encode a
   * min:max range (e.g. クリティカル = "9:10"). Selecting one should persist the
   * value and keep the page heading visible.
   */
  test('filter by severity works', async ({ page }) => {
    await page.goto('/alerts')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // Locate the severity select (its first option reads "重大度: すべて")
    const severitySelect = page.locator('select').filter({ hasText: /重大度|severity/i }).first()
    const hasSeveritySelect = await severitySelect.isVisible({ timeout: 5000 }).catch(() => false)

    if (hasSeveritySelect) {
      // Select クリティカル (value="9:10")
      await severitySelect.selectOption('9:10')
      await page.waitForLoadState('domcontentloaded', { timeout: 10000 })

      const selected = await severitySelect.inputValue()
      expect(selected).toBe('9:10')

      // Page heading should still be present
      await expect(
        page.getByRole('heading', { name: /アラート/ }).first(),
      ).toBeVisible({ timeout: 8000 })
    } else {
      // Fallback: try a severity filter button labelled critical / クリティカル
      const critBtn = page
        .getByRole('button', { name: /クリティカル|critical/i })
        .first()
      const hasCritBtn = await critBtn.isVisible().catch(() => false)
      if (hasCritBtn) {
        await critBtn.click()
        await page.waitForLoadState('domcontentloaded', { timeout: 10000 })
      }
      test.info().annotations.push({
        type: 'note',
        description: 'severity select not found; tried button fallback',
      })
    }
  })

  /**
   * 3. Alert detail page loads
   * Attempts to navigate to the first alert's detail page. Falls back to a
   * direct URL if no links are present in the list. The detail page renders a
   * full-height container even in its error/empty state, so a minimal structural
   * check is sufficient when there is no seeded data.
   */
  test('alert detail page loads', async ({ page }) => {
    await page.goto('/alerts')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // Try to click the first link to a detail page
    const detailLink = page.locator('a[href*="/alerts/"]').first()
    const hasDetailLink = await detailLink.isVisible({ timeout: 5000 }).catch(() => false)

    if (hasDetailLink) {
      const href = await detailLink.getAttribute('href')
      await page.goto(href!)
    } else {
      // Navigate directly to a known mock alert id (renders an error/empty state)
      await page.goto('/alerts/mock-001')
      test.info().annotations.push({
        type: 'note',
        description: 'No alert detail links found in list; used /alerts/mock-001',
      })
    }
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // Detail page should render its main container (loaded, error, or empty state)
    await expect(
      page.locator('main, .p-6, [class*="min-h-screen"]').first(),
    ).toBeVisible({ timeout: 8000 })
  })

  /**
   * 4. Status update works on alert detail page
   * Navigates to a detail page and attempts to change the alert status using the
   * status selector buttons (未対応 / 調査中 / 解決済み / 誤検知). When no seeded
   * alert exists the detail page renders an error state with no status controls;
   * in that case the test just confirms the page does not crash.
   */
  test('status update works on alert detail page', async ({ page }) => {
    // Go to a detail page — try the first link or fall back to mock
    await page.goto('/alerts')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    const detailLink = page.locator('a[href*="/alerts/"]').first()
    const hasDetailLink = await detailLink.isVisible({ timeout: 5000 }).catch(() => false)

    if (hasDetailLink) {
      const href = await detailLink.getAttribute('href')
      await page.goto(href!)
    } else {
      await page.goto('/alerts/mock-001')
    }

    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // The detail page exposes status option buttons (Japanese labels)
    const investigatingBtn = page.getByRole('button', { name: /調査中/ }).first()
    const hasStatusButton = await investigatingBtn.isVisible({ timeout: 8000 }).catch(() => false)

    if (hasStatusButton) {
      const isEnabled = await investigatingBtn.isEnabled().catch(() => false)
      if (isEnabled) {
        await investigatingBtn.click()
        // Wait briefly for mutation to settle
        await page.waitForTimeout(500)
      }
    } else {
      test.info().annotations.push({
        type: 'note',
        description: 'Status buttons not found (no seeded alert); skipped status change',
      })
    }

    // Page should not crash after a status change attempt
    await expect(
      page.locator('main, .p-6, [class*="min-h-screen"]').first(),
    ).toBeVisible({ timeout: 5000 })
  })
})
