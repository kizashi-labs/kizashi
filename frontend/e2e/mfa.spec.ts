import { test, expect } from '@playwright/test'

// MFA(TOTP) 有効ユーザー mfa@example.com は CI で SEED_E2E_MFA_USER=true により
// シードされる（server/cmd/api/main.go）。これらのテストは MFA プロンプト表示と
// 無効コード拒否を検証する（有効コード生成は不要）。
test.describe('MFA flow (TOTP)', () => {
  test('should prompt for MFA code after credentials for MFA-enabled user', async ({ page }) => {
    await page.goto('/login')

    // Fill credentials for MFA-enabled user
    await page.fill('input[autocomplete="username"]', 'mfa@example.com')
    await page.fill('input[autocomplete="current-password"]', 'Password123!')
    await page.click('button[type="submit"]')

    // Expect an MFA code entry screen
    // Look for a code input – could be placeholder "コード", "000000", or type="number"/"text" with maxlength 6
    const mfaInput = page
      .locator(
        'input[autocomplete="one-time-code"], input[placeholder="000000"], input[inputmode="numeric"]'
      )
      .first()

    await expect(mfaInput).toBeVisible({ timeout: 10000 })
  })

  test('should show error when invalid MFA code is submitted', async ({ page }) => {
    await page.goto('/login')

    await page.fill('input[autocomplete="username"]', 'mfa@example.com')
    await page.fill('input[autocomplete="current-password"]', 'Password123!')
    await page.click('button[type="submit"]')

    // Wait for MFA input
    const mfaInput = page
      .locator(
        'input[autocomplete="one-time-code"], input[placeholder="000000"], input[inputmode="numeric"]'
      )
      .first()

    await expect(mfaInput).toBeVisible({ timeout: 10000 })

    // Enter 6 zeros – will be rejected by the server
    await mfaInput.fill('000000')

    // Submit the MFA form
    const submitButton = page.getByRole('button', { name: /確認|verify|送信|submit/i }).first()
    const hasSubmit = await submitButton.isVisible().catch(() => false)
    if (hasSubmit) {
      await submitButton.click()
    } else {
      await mfaInput.press('Enter')
    }

    // Expect an error message about invalid code
    await expect(
      page.getByText(/無効|invalid|incorrect|コードが正しくありません|error/i).first()
    ).toBeVisible({ timeout: 8000 })
  })

  test('should allow re-entering credentials after navigating back', async ({ page }) => {
    await page.goto('/login')

    await page.fill('input[autocomplete="username"]', 'mfa@example.com')
    await page.fill('input[autocomplete="current-password"]', 'Password123!')
    await page.click('button[type="submit"]')

    // Wait for MFA screen to appear
    const mfaInput = page
      .locator(
        'input[autocomplete="one-time-code"], input[placeholder="000000"], input[inputmode="numeric"]'
      )
      .first()

    await expect(mfaInput).toBeVisible({ timeout: 10000 })

    // Navigate back to login
    await page.goBack()

    // Or go directly to /login if goBack doesn't land on it
    const currentURL = page.url()
    if (!currentURL.includes('/login')) {
      await page.goto('/login')
    }

    // Verify we can see the credential inputs again
    await expect(page.locator('input[autocomplete="username"]').first()).toBeVisible({ timeout: 8000 })
    await expect(page.locator('input[autocomplete="current-password"]').first()).toBeVisible({ timeout: 8000 })
  })
})
