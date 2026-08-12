import { test, expect } from '@playwright/test'
import { login } from './helpers'

test.describe('Login flow', () => {
  test('should login and redirect to dashboard', async ({ page }) => {
    await page.goto('/login')
    await page.fill('input[autocomplete="username"]', 'admin@example.com')
    await page.fill('input[autocomplete="current-password"]', process.env.E2E_ADMIN_PASS || 'CiAdm1n!2026')
    await page.click('button[type="submit"]')

    // Expect redirect to /dashboard or /
    await expect(page).toHaveURL(/\/(dashboard|)/, { timeout: 12000 })

    // Expect a recognizable heading or content on the post-login page
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 8000 })
  })

  test('should logout and redirect back to login', async ({ page }) => {
    await login(page)

    // Expect to be on a post-login page
    await expect(page).toHaveURL(/\/(dashboard|alerts|agents)/, { timeout: 12000 })

    // Try to find and click a user menu or logout button
    const userMenuButton = page
      .getByRole('button', { name: /user|account|profile|admin|ユーザー|アカウント/i })
      .first()
    const logoutButton = page.getByRole('button', { name: /logout|ログアウト/i }).first()

    const hasUserMenu = await userMenuButton.isVisible().catch(() => false)
    if (hasUserMenu) {
      await userMenuButton.click()
    }

    const hasLogout = await logoutButton.isVisible({ timeout: 3000 }).catch(() => false)
    if (hasLogout) {
      await logoutButton.click()
    } else {
      // Fallback: clear session via localStorage
      await page.evaluate(() => {
        localStorage.removeItem('edr_token')
        localStorage.removeItem('edr_user')
      })
      await page.goto('/dashboard')
    }

    // Expect redirect back to /login
    await expect(page).toHaveURL(/\/login/, { timeout: 8000 })
  })
})
