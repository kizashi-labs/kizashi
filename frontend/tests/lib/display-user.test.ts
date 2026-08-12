import { describe, it, expect } from 'vitest'
import { displayUser } from '@/lib/display-user'

describe('displayUser', () => {
  // ─── Fallback branch (empty/blank input) ──────────────────────────────────
  it('null は既定のフォールバックを返す', () => {
    expect(displayUser(null)).toBe('—')
  })

  it('undefined は既定のフォールバックを返す', () => {
    expect(displayUser(undefined)).toBe('—')
  })

  it('空文字・空白のみはフォールバックを返す', () => {
    expect(displayUser('')).toBe('—')
    expect(displayUser('   ')).toBe('—')
  })

  it('カスタムフォールバックを尊重する', () => {
    expect(displayUser(null, 'system')).toBe('system')
  })

  // ─── UUID branch ──────────────────────────────────────────────────────────
  it('UUID は先頭8文字+省略記号に短縮する', () => {
    expect(displayUser('3f2504e0-4f89-41d3-9a0c-0305e82c3301')).toBe('3f2504e0…')
  })

  it('大文字を含む UUID も短縮する（大小無視）', () => {
    expect(displayUser('3F2504E0-4F89-41D3-9A0C-0305E82C3301')).toBe('3F2504E0…')
  })

  // ─── Email branch ─────────────────────────────────────────────────────────
  it('メールアドレスはローカルパートを返す', () => {
    expect(displayUser('alice@example.com')).toBe('alice')
  })

  // ─── Passthrough branch ───────────────────────────────────────────────────
  it('表示名はそのまま返す', () => {
    expect(displayUser('Alice Smith')).toBe('Alice Smith')
  })

  it('UUID に見えるが形式が不完全な文字列はそのまま返す', () => {
    // 短すぎて UUID 正規表現に一致しない → passthrough
    expect(displayUser('3f2504e0-4f89')).toBe('3f2504e0-4f89')
  })
})
