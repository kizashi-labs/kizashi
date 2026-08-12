import { test, expect } from '@playwright/test'

test.describe('パスワード変更ページ', () => {
  test('ページが正しくレンダリングされる（トークンあり）', async ({ page }) => {
    // トークンをセットしてアクセス
    await page.goto('/login')
    // localStorage にダミートークンをセット（JWT形式）
    await page.evaluate(() => {
      // ダミーJWT（有効期限切れだがUIテスト用）
      localStorage.setItem('edr_token', 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.dummy')
      localStorage.setItem('edr_user', JSON.stringify({ id: 'admin', email: 'admin@localhost', role: 'admin', must_change_password: true }))
    })
    await page.goto('/change-password')

    await expect(page.getByText('パスワードの変更')).toBeVisible({ timeout: 5000 })
    await expect(page.getByPlaceholder('8文字以上')).toBeVisible()
    await expect(page.getByPlaceholder('もう一度入力')).toBeVisible()
  })

  test('パスワードが一致しない場合にエラーが表示される', async ({ page }) => {
    await page.goto('/login')
    await page.evaluate(() => {
      localStorage.setItem('edr_token', 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.dummy')
      localStorage.setItem('edr_user', JSON.stringify({ id: 'admin', email: 'admin@localhost', role: 'admin' }))
    })
    await page.goto('/change-password')

    await page.getByPlaceholder('8文字以上').fill('NewPassword1!')
    await page.getByPlaceholder('もう一度入力').fill('DifferentPassword!')
    await expect(page.getByText('パスワードが一致しません')).toBeVisible({ timeout: 3000 })
  })

  test('強度バーが表示される', async ({ page }) => {
    await page.goto('/login')
    await page.evaluate(() => {
      localStorage.setItem('edr_token', 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.dummy')
      localStorage.setItem('edr_user', JSON.stringify({ id: 'admin', email: 'admin@localhost', role: 'admin' }))
    })
    await page.goto('/change-password')

    await page.getByPlaceholder('8文字以上').fill('weak')
    await expect(page.getByText(/強度:/)).toBeVisible({ timeout: 3000 })
  })

  test('8文字未満はボタンが無効', async ({ page }) => {
    await page.goto('/login')
    await page.evaluate(() => {
      localStorage.setItem('edr_token', 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.dummy')
      localStorage.setItem('edr_user', JSON.stringify({ id: 'admin', email: 'admin@localhost', role: 'admin' }))
    })
    await page.goto('/change-password')

    await page.getByPlaceholder('8文字以上').fill('short')
    await page.getByPlaceholder('もう一度入力').fill('short')
    const submitBtn = page.getByRole('button', { name: /パスワードを変更する/ })
    await expect(submitBtn).toBeDisabled()
  })
})
