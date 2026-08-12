import { chromium, FullConfig } from '@playwright/test'
import * as path from 'path'
import * as fs from 'fs'

// シード済み実ユーザーを既定にする。フォールバック admin ユーザーのトークンは
// user_id が UUID でないため保護ルートで拒否される（storageState が無効化する）。
const ADMIN_USER = process.env.E2E_ADMIN_USER || 'admin@example.com'
const ADMIN_PASS = process.env.E2E_ADMIN_PASS || 'CiAdm1n!2026'

/**
 * グローバルセットアップ: 管理者トークンを一度だけ取得してストレージステートに保存。
 * これにより各テストでのログイン API 呼び出しを排除し、レートリミッターを回避する。
 */
async function globalSetup(_config: FullConfig) {
  const baseURL = process.env.BASE_URL || process.env.E2E_BASE_URL || 'http://localhost:3000'
  const browser = await chromium.launch()
  const context = await browser.newContext({ baseURL })
  const page = await context.newPage()

  const resp = await page.request.post('/api/v1/auth/login', {
    data: { username: ADMIN_USER, password: ADMIN_PASS },
  })
  const status = resp.status()
  const body = await resp.text()
  if (!resp.ok()) {
    await browser.close()
    throw new Error(`Global setup login failed: ${status} ${body}`)
  }

  const data = JSON.parse(body)
  const user = data.user ?? { id: 'admin', email: 'admin@localhost', role: 'admin' }

  // コンテキストを確立してから localStorage にトークンを注入
  await page.goto('/login')
  await page.evaluate(
    ({ t, u }: { t: string; u: object }) => {
      localStorage.setItem('edr_token', t)
      localStorage.setItem('edr_user', JSON.stringify(u))
    },
    { t: data.token, u: user },
  )

  // ストレージステートを保存（以降のテストで再利用）
  const authDir = path.join(__dirname, '.auth')
  if (!fs.existsSync(authDir)) fs.mkdirSync(authDir, { recursive: true })
  await context.storageState({ path: path.join(authDir, 'admin.json') })
  await browser.close()
}

export default globalSetup
