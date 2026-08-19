import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'

// The 組織管理 screen was backed by /api/v1/admin/organizations, which read a
// parallel `organizations` table that no foreign key in the schema pointed at.
// Every tenant_id references `tenants`, so an organization created here could
// never own an agent, a user or an alert, and the server's counts for it were
// structurally zero. Migration 380 removed the table, the handler and the
// routes; this page now reads /api/v1/admin/tenants.
//
// Three defects on this side went with the move, and each is pinned below
// because each made a failure look like a success:
//
//   toggleEnabled
//     setOrgs(prev => prev.map(...))   // local state only
//     showToast('組織を更新しました')    // ...and says it saved
//   No request was ever made. Disabling an organization did nothing.
//
//   handleSubmit's catch
//     const mockOrg = { id: `org-${Date.now()}`, ... }
//     onCreated(mockOrg)
//   A rejected creation was added to the list with a fabricated id, so it read
//   as successful until reload.
//
//   The list
//     apiFetchList<Organization>(...)  // API answers snake_case
//     interface Organization { agentLimit, agentCount, ... }  // declared camelCase
//   Every numeric column rendered undefined. There is an explicit adapter now.

const PAGE = path.join(__dirname, '..', '..', 'app', 'admin', 'organizations', 'page.tsx')

// Comments are stripped first: the fixes are documented by quoting the code
// they replaced, so a scan that reads comments finds the defect it removed.
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
}

const src = stripComments(readFileSync(PAGE, 'utf-8'))

// fn isolates one function body so an assertion about toggleEnabled cannot be
// satisfied by unrelated code elsewhere on a 470-line page.
function fn(name: string): string {
  const start = src.indexOf(name)
  expect(start, `${name} が page.tsx にありません`).toBeGreaterThan(-1)
  const rest = src.slice(start)
  const end = rest.indexOf('\n  }\n')
  return end === -1 ? rest : rest.slice(0, end)
}

describe('組織管理画面のバックエンド', () => {
  it('削除された organizations API を参照しない', () => {
    expect(
      src.includes('/api/v1/admin/organizations'),
      'migration 380 で削除されたエンドポイントを呼んでいます。' +
        'テナントは /api/v1/admin/tenants です',
    ).toBe(false)
    expect(
      src.includes('/api/v1/org/current') || src.includes('/api/v1/org/settings'),
      '削除された組織設定エンドポイントを呼んでいます',
    ).toBe(false)
  })

  it('tenants API を参照する', () => {
    expect(
      src.includes('/api/v1/admin/tenants'),
      'テナント API を参照していません',
    ).toBe(true)
  })

  it('snake_case の応答を明示的に変換する', () => {
    // Asserted on the call site, not merely on the name appearing somewhere:
    // the adapter existing while the list bypasses it is the exact state that
    // rendered every numeric column as undefined.
    expect(
      /\.map\(\s*adaptTenant\s*\)/.test(src),
      '一覧が adaptTenant を通していません。' +
        'API は max_agents / agent_count / is_active を返し、画面は camelCase を期待するため、' +
        '変換が無いと数値列がすべて undefined になります',
    ).toBe(true)
    expect(
      /function adaptTenant/.test(src),
      'adaptTenant の定義がありません',
    ).toBe(true)
    for (const key of ['max_agents', 'max_users', 'agent_count', 'user_count', 'is_active']) {
      expect(src.includes(key), `${key} を読んでいません`).toBe(true)
    }
  })
})

describe('書き込みが実際に行われる', () => {
  it('有効・無効の切り替えが API を呼ぶ', () => {
    const body = fn('const toggleEnabled')
    expect(
      body.includes('apiFetch'),
      '有効・無効の切り替えがローカル state だけを変更しています。' +
        '保存されていないのに「更新しました」と表示されます',
    ).toBe(true)
    expect(
      body.includes('is_active'),
      '切り替えが is_active を送っていません',
    ).toBe(true)
  })

  it('作成失敗時にモックの組織を捏造しない', () => {
    expect(
      /id:\s*`org-\$\{Date\.now\(\)\}`/.test(src),
      '作成失敗時に偽の id を持つ行を一覧へ追加しています。' +
        '失敗が成功と区別できません',
    ).toBe(false)
    const body = fn('const handleSubmit')
    expect(
      body.includes('setError'),
      '作成の失敗が利用者に伝わりません',
    ).toBe(true)
  })
})

describe('存在しない設定項目を表示しない', () => {
  it('SSO許可とデータ保持日数が残っていない', () => {
    // Both lived in organizations.settings, whose keys nothing in the Go tree
    // ever read — and the form POSTed "sso_allowed" against an "allow_sso"
    // JSON tag, so the toggle did not even reach the column it was aimed at.
    for (const gone of ['ssoAllowed', 'retentionDays', 'sso_allowed', 'SSO許可']) {
      expect(
        src.includes(gone),
        `${gone} が残っています。保存先が無い設定項目です`,
      ).toBe(false)
    }
  })
})
