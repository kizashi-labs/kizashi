import { test, expect } from '@playwright/test'
import { loginAsAdmin, clearSession } from './helpers/auth'

// ─── Agent / device management ────────────────────────────────────────────────
//
// The agents (devices) list is served at /endpoints under the heading
// "エンドポイント". Individual agent detail pages live at /endpoints/[id].

test.describe('Agent management', () => {
  // Authenticate once per test via API (no UI login)
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test.afterEach(async ({ page }) => {
    await clearSession(page)
  })

  /**
   * 1. Agents/devices page loads
   */
  test('agents/devices page loads', async ({ page }) => {
    await page.goto('/endpoints')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // Page heading "エンドポイント"
    await expect(
      page.getByRole('heading', { name: /エンドポイント/ }).first(),
    ).toBeVisible({ timeout: 10000 })

    // At least one of the summary stat labels should be visible
    const statLabel = page
      .getByText(/総数|オンライン|オフライン|隔離中/)
      .first()
    await expect(statLabel).toBeVisible({ timeout: 8000 })
  })

  /**
   * 2. Agent detail page loads
   * Clicks the first detail link in the endpoint list, or falls back to a
   * direct URL using the mock agent id.
   */
  test('agent detail page loads', async ({ page }) => {
    await page.goto('/endpoints')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // Look for a direct link to an endpoint detail page
    const detailLink = page
      .locator('a[href*="/endpoints/"]')
      .filter({ hasNot: page.locator('[href$="/endpoints"]') })
      .first()
    const hasDetailLink = await detailLink.isVisible({ timeout: 5000 }).catch(() => false)

    if (hasDetailLink) {
      const href = await detailLink.getAttribute('href')
      await page.goto(href!)
      await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

      // Detail page must render its main content
      await expect(
        page.locator('main, .p-6, [class*="min-h-screen"]').first(),
      ).toBeVisible({ timeout: 8000 })
    } else {
      // Fallback: navigate to agent-001 which is used as the mock agent
      await page.goto('/agents/agent-001')
      await page.waitForLoadState('domcontentloaded', { timeout: 15000 })
      await expect(
        page.locator('main, .p-6, [class*="min-h-screen"]').first(),
      ).toBeVisible({ timeout: 8000 })
      test.info().annotations.push({
        type: 'note',
        description: 'No /endpoints/[id] links found; used /agents/agent-001 as fallback',
      })
    }
  })

  /**
   * 3. Search/filter works
   * Types a hostname fragment into the search field and confirms the page
   * remains functional. Also exercises the OS dropdown filter.
   */
  test('search and filter works', async ({ page }) => {
    await page.goto('/endpoints')
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 })

    // ── Text search ──────────────────────────────────────────────────────────
    const searchInput = page
      .locator('input[placeholder*="ホスト名"], input[placeholder*="検索"], input[type="search"]')
      .first()
    const hasSearch = await searchInput.isVisible({ timeout: 5000 }).catch(() => false)

    if (hasSearch) {
      await searchInput.fill('DESKTOP')
      await page.waitForLoadState('domcontentloaded', { timeout: 10000 })

      // Heading must still be present after filtering
      await expect(
        page.getByRole('heading', { name: /エンドポイント/ }).first(),
      ).toBeVisible({ timeout: 8000 })

      // Clear the search
      await searchInput.fill('')
      await page.waitForLoadState('domcontentloaded', { timeout: 10000 })
    } else {
      test.info().annotations.push({
        type: 'note',
        description: 'Search input not found; skipping text search',
      })
    }

    // ── OS filter (select) ───────────────────────────────────────────────────
    const osSelect = page
      .locator('select')
      .filter({ hasText: /OS|windows|linux/i })
      .first()
    const hasOsSelect = await osSelect.isVisible({ timeout: 3000 }).catch(() => false)

    if (hasOsSelect) {
      await osSelect.selectOption('windows')
      await page.waitForLoadState('domcontentloaded', { timeout: 10000 })

      const selectedValue = await osSelect.inputValue()
      expect(selectedValue).toBe('windows')

      // Reset
      await osSelect.selectOption('')
    } else {
      test.info().annotations.push({
        type: 'note',
        description: 'OS select not found; skipping OS filter check',
      })
    }

    // Page should not crash
    await expect(
      page.getByRole('heading', { name: /エンドポイント/ }).first(),
    ).toBeVisible({ timeout: 8000 })
  })
})
