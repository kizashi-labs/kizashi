import { test, expect } from '@playwright/test'

// ─── UEBA (ユーザー行動分析) ───────────────────────────────────────────────────

test.describe('UEBA', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ueba')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show UEBA page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show behavior analytics content', async ({ page }) => {
    const content = page.locator('[class*="card"], table, [class*="space-y"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── インサイダー脅威 ──────────────────────────────────────────────────────────

test.describe('インサイダー脅威', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/insider-threat')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show insider threat page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show threat indicators or empty state', async ({ page }) => {
    const content = page.locator('table, [class*="card"], [class*="space-y"], p').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── 脅威マップ ────────────────────────────────────────────────────────────────

test.describe('脅威マップ', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/threat-map')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show threat map page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show map or geo visualization', async ({ page }) => {
    const content = page.locator('canvas, svg, [class*="map"], [class*="geo"], [class*="card"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── リスクスコア ──────────────────────────────────────────────────────────────

test.describe('リスクスコア', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/risk-score')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show risk score page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show risk score content', async ({ page }) => {
    // リスクスコアページは grid レイアウト + ゲージ(svg) + ローカル計算カードを描画する
    const content = page.locator('[class*="score"], [class*="card"], [class*="stat"], [class*="grid"], svg, table').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})

// ─── セキュリティポスチャー ────────────────────────────────────────────────────

test.describe('セキュリティポスチャー', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/security-posture')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test('should show security posture page', async ({ page }) => {
    const heading = page.getByRole('heading').first()
    await expect(heading).toBeVisible({ timeout: 10_000 })
  })

  test('should show posture metrics or score', async ({ page }) => {
    const content = page.locator('[class*="card"], [class*="score"], table, [class*="stat"]').first()
    await expect(content).toBeVisible({ timeout: 8_000 })
  })
})
