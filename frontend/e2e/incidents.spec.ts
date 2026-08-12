import { test, expect } from '@playwright/test'
import { loginAsAdmin, clearSession } from './helpers/auth'

// ─── インシデント管理 ──────────────────────────────────────────────────────────

test.describe('インシデント管理', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/incidents')
    await page.waitForLoadState('domcontentloaded', { timeout: 15_000 })
  })

  test.afterEach(async ({ page }) => {
    await clearSession(page)
  })

  /**
   * 1. should load incidents list
   * /incidents ページが正常に読み込まれ、ヘッダーと一覧エリアが表示されること。
   */
  test('should load incidents list', async ({ page }) => {
    // ページヘッダー「インシデント管理」が表示されること
    await expect(page.getByRole('heading', { name: 'インシデント管理' })).toBeVisible({
      timeout: 10_000,
    })

    // 「新規インシデント」ボタンが表示されること
    await expect(page.getByRole('button', { name: /新規インシデント/ })).toBeVisible({
      timeout: 8_000,
    })

    // ステータスフィルタータブが表示されること
    await expect(page.getByRole('button', { name: 'すべて' }).first()).toBeVisible({
      timeout: 8_000,
    })

    // 一覧エリアの読み込みが完了し、リスト or 「インシデントがありません」が
    // 表示されること（非同期 fetch を auto-retry で待つ。即時 isVisible だと
    // 「読み込み中...」を誤検知して失敗する）。
    await expect(
      page.getByText('インシデントがありません').or(page.locator('div.space-y-3').first()),
    ).toBeVisible({ timeout: 15_000 })
  })

  /**
   * 2. should create new incident
   * 「新規インシデント」ボタンをクリックしてフォームを入力し、
   * 保存すると一覧に新しいインシデントが表示されること。
   */
  test('should create new incident', async ({ page }) => {
    const uniqueTitle = `E2Eテスト用インシデント_${Date.now()}`

    // 「新規インシデント」ボタンをクリック
    await page.getByRole('button', { name: /新規インシデント/ }).click()

    // フォームが表示されること
    await expect(page.getByText('新しいインシデント')).toBeVisible({ timeout: 5_000 })

    // タイトルを入力
    const titleInput = page.getByPlaceholder('例: ランサムウェア感染疑い')
    await expect(titleInput).toBeVisible({ timeout: 5_000 })
    await titleInput.fill(uniqueTitle)

    // 説明を入力
    const descInput = page.getByPlaceholder('インシデントの詳細')
    await descInput.fill('Playwright E2E テストから作成されたインシデント')

    // 重大度を設定（デフォルト 7 をそのまま使用）
    // ステータスを設定（デフォルト「未対応」をそのまま使用）

    // 「作成」ボタンをクリック
    await page.getByRole('button', { name: '作成' }).click()

    // フォームが閉じること（成功後に非表示になる）
    await expect(page.getByText('新しいインシデント')).not.toBeVisible({ timeout: 10_000 })

    // 作成したインシデントが一覧に表示されること
    await page.waitForLoadState('domcontentloaded', { timeout: 10_000 })
    await expect(page.getByText(uniqueTitle).first()).toBeVisible({ timeout: 10_000 })
  })

  /**
   * 3. should update incident status
   * インシデント詳細ページでステータスを変更して保存できること。
   */
  test('should update incident status', async ({ page }) => {
    // インシデントが存在することを確認
    const emptyMessage = page.getByText('インシデントがありません')
    const isEmpty = await emptyMessage.isVisible().catch(() => false)

    if (isEmpty) {
      // インシデントが存在しない場合は作成してからテスト
      const uniqueTitle = `E2Eステータステスト_${Date.now()}`

      await page.getByRole('button', { name: /新規インシデント/ }).click()
      await page.getByPlaceholder('例: ランサムウェア感染疑い').fill(uniqueTitle)
      await page.getByRole('button', { name: '作成' }).click()
      await expect(page.getByText('新しいインシデント')).not.toBeVisible({ timeout: 10_000 })
      await page.waitForLoadState('domcontentloaded', { timeout: 10_000 })
    }

    // 最初のインシデントをクリックして詳細ページに移動
    const firstIncident = page.locator('div.space-y-3 > div').first()
    await expect(firstIncident).toBeVisible({ timeout: 8_000 })
    await firstIncident.click()

    // 詳細ページに遷移すること
    await expect(page).toHaveURL(/\/incidents\/[a-z0-9-]+/, { timeout: 10_000 })
    await page.waitForLoadState('domcontentloaded', { timeout: 10_000 })

    // 詳細ページの「概要」タブには「ステータス遷移」セクションがあり、
    // 「<次状態> に変更」ボタンでステータスを更新する（編集フォームではない）。
    await expect(page.getByRole('heading', { name: 'インシデント情報' })).toBeVisible({ timeout: 10_000 })

    const transitionBtn = page.getByRole('button', { name: /に変更$/ }).first()
    const hasTransition = await transitionBtn.isVisible({ timeout: 8_000 }).catch(() => false)

    if (hasTransition) {
      const label = (await transitionBtn.textContent())?.replace(/\s+/g, '') ?? ''
      // 「<状態> に変更」→ 対象の状態名を抽出（例: 「調査中 に変更」→「調査中」）
      const target = label.replace('に変更', '').trim()
      await transitionBtn.click()

      // 更新後、その状態バッジが表示されること（クローズ済み等で遷移先が無い場合はスキップ）
      if (target) {
        await expect(page.getByText(target).first()).toBeVisible({ timeout: 10_000 })
      }
    } else {
      // 遷移先が無い（closed 等）場合は、ステータスバッジが描画されていればよい
      await expect(page.getByText(/未対応|調査中|封じ込め済み|解決済み|クローズ/).first())
        .toBeVisible({ timeout: 8_000 })
    }
  })

  /**
   * 4. should add note to incident
   * インシデント詳細ページでノートを入力して追加できること。
   */
  test('should add note to incident', async ({ page }) => {
    // インシデントが存在することを確認
    const emptyMessage = page.getByText('インシデントがありません')
    const isEmpty = await emptyMessage.isVisible().catch(() => false)

    if (isEmpty) {
      // インシデントが存在しない場合は作成してからテスト
      const uniqueTitle = `E2Eノートテスト_${Date.now()}`

      await page.getByRole('button', { name: /新規インシデント/ }).click()
      await page.getByPlaceholder('例: ランサムウェア感染疑い').fill(uniqueTitle)
      await page.getByRole('button', { name: '作成' }).click()
      await expect(page.getByText('新しいインシデント')).not.toBeVisible({ timeout: 10_000 })
      await page.waitForLoadState('domcontentloaded', { timeout: 10_000 })
    }

    // 最初のインシデントをクリックして詳細ページに移動
    const firstIncident = page.locator('div.space-y-3 > div').first()
    await expect(firstIncident).toBeVisible({ timeout: 8_000 })
    await firstIncident.click()

    // 詳細ページに遷移すること
    await expect(page).toHaveURL(/\/incidents\/[a-z0-9-]+/, { timeout: 10_000 })
    await page.waitForLoadState('domcontentloaded', { timeout: 10_000 })

    // ノート入力エリアは「ノート」タブ内にあるため、まずタブを開く
    const notesTab = page.getByRole('button', { name: 'ノート' }).first()
    await expect(notesTab).toBeVisible({ timeout: 8_000 })
    await notesTab.click()

    // ノート入力エリアが表示されること
    const noteTextarea = page.getByPlaceholder(/ノートを追加/)
    await expect(noteTextarea).toBeVisible({ timeout: 8_000 })

    // ノートの内容を入力
    const noteContent = `E2Eテスト用ノート ${Date.now()}`
    await noteTextarea.fill(noteContent)

    // 「追加」ボタンをクリック（サイドバーの「お気に入りに追加」と部分一致して
    // strict mode 違反になるため exact 一致で限定する）
    const addNoteButton = page.getByRole('button', { name: '追加', exact: true })
    await expect(addNoteButton).toBeVisible({ timeout: 5_000 })
    await addNoteButton.click()

    // ノートが追加されてテキストエリアが空になること
    await expect(noteTextarea).toHaveValue('', { timeout: 10_000 })

    // 追加したノートが一覧に表示されること
    await page.waitForLoadState('domcontentloaded', { timeout: 10_000 })
    await expect(page.getByText(noteContent)).toBeVisible({ timeout: 10_000 })
  })
})
