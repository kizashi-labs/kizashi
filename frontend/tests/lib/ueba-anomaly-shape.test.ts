import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'
import { toAnomalyItem } from '../../lib/ueba'

// この画面の異常一覧は空のままでした。呼び先が /admin/uba/anomalies で、
// サーバにあるのは /admin/ueba/anomalies — e が1文字足りません。404 を
// .catch(() => []) が飲み込むので、症状は「異常なし」でした。
//
// 経路だけ直すと、今度は空欄の行が並びます。サーバは username /
// anomaly_type / score / created_at で返し、画面は user / type /
// risk_delta / timestamp を読むからです。両方を固定します。
//
// 言語をまたぐ名前の対応で、どちらのコンパイラも見ていません。
//
// 写す関数が lib/ueba.ts にあるのは、Next.js の App Router がページ
// ファイルからの export を default と決まった数個に限っているからです。
// page.tsx に置いたままだとビルドが
// 「"toAnomalyItem" is not a valid Page export field」で落ちます。
// tsc も vitest も通り、npm run build だけが落ちました。

const SRC = readFileSync(
  join(process.cwd(), 'app/admin/user-behavior-analytics/page.tsx'),
  'utf8'
)
const HANDLER = readFileSync(
  join(process.cwd(), '..', 'server/internal/api/handlers/ueba_advanced_handler.go'),
  'utf8'
)

describe('UEBA 異常一覧', () => {
  it('サーバにある経路を呼んでいる', () => {
    expect(SRC, '/admin/uba/anomalies にはルートがありません').not.toContain(
      "'/api/v1/admin/uba/anomalies'"
    )
    expect(SRC).toContain("'/api/v1/admin/ueba/anomalies'")
  })

  it('サーバが返すキー名を読んでいる', () => {
    // ハンドラの json タグが変われば、ここで気づきます。
    for (const tag of ['json:"username"', 'json:"anomaly_type"', 'json:"score"', 'json:"created_at"']) {
      expect(HANDLER, `ueba_advanced_handler.go に ${tag} がありません`).toContain(tag)
    }
  })

  it('1行を画面の形に写せる', () => {
    expect(
      toAnomalyItem({
        id: 'a1',
        username: 'tanaka',
        anomaly_type: 'off_hours_access',
        description: '深夜のアクセス',
        score: 42.6,
        created_at: '2026-03-18T02:30:00Z',
      })
    ).toEqual({
      id: 'a1',
      timestamp: '2026-03-18T02:30:00Z',
      user: 'tanaka',
      type: 'off_hours_access',
      description: '深夜のアクセス',
      risk_delta: 43,
    })
  })

  it('score が無くても落ちない', () => {
    const row = {
      id: 'a2', username: 'u', anomaly_type: 'x', description: '',
      score: undefined as unknown as number, created_at: '2026-03-18T00:00:00Z',
    }
    expect(toAnomalyItem(row).risk_delta).toBe(0)
  })
})
