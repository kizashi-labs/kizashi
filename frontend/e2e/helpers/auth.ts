import { Page } from '@playwright/test'

const ADMIN_USER = process.env.E2E_ADMIN_USER || 'admin'
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || 'admin'
const ANALYST_USER = process.env.E2E_ANALYST_USER || 'analyst'
const ANALYST_PASS = process.env.E2E_ANALYST_PASS || 'analyst'

/**
 * POST /api/v1/auth/login でトークンを取得し、
 * localStorage に edr_token を設定してページをリロードする。
 */
async function loginAs(page: Page, username: string, password: string): Promise<void> {
  // まずページを開いてコンテキストを確立する（localhost オリジンが必要）
  await page.goto('/login')

  // API 経由でトークンを取得
  const resp = await page.request.post('/api/v1/auth/login', {
    data: { username, password },
  })

  if (!resp.ok()) {
    throw new Error(
      `Login API failed for user "${username}": ${resp.status()} ${await resp.text()}`
    )
  }

  const data = await resp.json()
  const token: string = data.token
  const user = data.user ?? {
    id: username,
    email: `${username}@localhost`,
    role: username === 'admin' ? 'admin' : 'analyst',
  }

  // localStorage にトークンとユーザー情報を注入
  await page.evaluate(
    ({ t, u }: { t: string; u: object }) => {
      localStorage.setItem('edr_token', t)
      localStorage.setItem('edr_user', JSON.stringify(u))
    },
    { t: token, u: user }
  )

  // ダッシュボードに遷移（パスワード変更要求がある場合は change-password に遷移する）
  if (data.must_change_password) {
    await page.goto('/change-password')
    await page.waitForURL(/\/change-password/, { timeout: 10_000 })
  } else {
    await page.goto('/dashboard')
    await page.waitForURL(/\/dashboard/, { timeout: 10_000 })
  }
}

/**
 * admin / admin でログインする。
 * localStorage に edr_token を設定してダッシュボードへ遷移する。
 */
export async function loginAsAdmin(page: Page): Promise<void> {
  await loginAs(page, ADMIN_USER, ADMIN_PASS)
}

/**
 * analyst ユーザーでログインする。
 * localStorage に edr_token を設定してダッシュボードへ遷移する。
 */
export async function loginAsAnalyst(page: Page): Promise<void> {
  await loginAs(page, ANALYST_USER, ANALYST_PASS)
}

/**
 * localStorage のトークンをクリアしてセッションを破棄する。
 */
export async function clearSession(page: Page): Promise<void> {
  await page.evaluate(() => {
    localStorage.removeItem('edr_token')
    localStorage.removeItem('edr_user')
  })
}
