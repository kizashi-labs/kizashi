import { Page } from '@playwright/test'

// 認証情報は環境変数優先（CI は E2E_ADMIN_USER / E2E_ADMIN_PASS を注入する）。
// ローカル実行時は各自の admin 認証情報を環境変数で上書きすること。
// 既定はシード済み実ユーザー admin@example.com。フォールバック admin ユーザーは
// user_id が UUID でないため保護ルートで拒否され /dashboard に到達できない。
const ADMIN_USER = process.env.E2E_ADMIN_USER || 'admin@example.com'
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || 'CiAdm1n!2026'

export async function login(page: Page, user = ADMIN_USER, password = ADMIN_PASS) {
  await page.goto('/login')
  // ログイン画面のユーザー名欄は type="email" ではなく
  // autocomplete="username" の text input（app/login/page.tsx）。
  await page.fill('input[autocomplete="username"]', user)
  await page.fill('input[autocomplete="current-password"]', password)
  await page.click('button[type="submit"]')
  await page.waitForURL(/\/(dashboard|alerts|agents|\?)/, { timeout: 10000 })
}
