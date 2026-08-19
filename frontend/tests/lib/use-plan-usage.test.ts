import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'

// usePlan reported agentUsed as 0 on every deployment that has ever run, for
// two independent reasons stacked on top of each other:
//
//   1. the queryFn unwrapped the response to `res.license` and dropped the
//      sibling `usage` object one line before anything read it;
//   2. even with it kept, the code looked for `usage.agents`, and the server
//      sends `agents_active` (the json tag on license.UsageSummary).
//
// Both produce undefined, `?? 0` turns that into zero, and zero is a number
// the rest of the hook believes:
//
//   isNearFreeLimit = plan === 'free' && agentUsed >= 4        → never
//   isAtFreeLimit   = plan === 'free' && agentUsed >= limit    → never
//
// The Free-plan cap banner on the endpoints page has therefore never appeared.
// Nothing errored; the number was simply always the reassuring one.
//
// The field names are the contract between two languages and no compiler
// checks it, so it is checked here.

const SRC = readFileSync(join(process.cwd(), 'lib/usePlan.ts'), 'utf8')

describe('usePlan の使用量', () => {
  it('サーバが送るキー名を読んでいる', () => {
    expect(SRC, 'agents_active ではなく agents を読んでいます').toContain(
      'usage?.agents_active'
    )
    expect(SRC, '存在しない usage.agents をまだ読んでいます').not.toMatch(
      /usage\?\.agents\s*\?\?/
    )
  })

  it('レスポンスを開くときに usage を捨てていない', () => {
    // `return res.license` だけを返すと、その隣の usage は読まれる前に消えます。
    expect(SRC, 'res.license だけを返しており usage が落ちています').not.toMatch(
      /return\s+res\.license\s*$/m
    )
    expect(SRC).toMatch(/usage:\s*res\.usage/)
  })

  it('サーバの UsageSummary と同じ名前で型を持っている', () => {
    for (const field of [
      'agents_active',
      'agent_limit',
      'users_active',
      'user_limit',
      'can_add_agents',
    ]) {
      expect(SRC, `UsageSummary に ${field} がありません`).toContain(field)
    }
  })

  it('Freeプランの上限判定が agentUsed を見ている', () => {
    // ここが上限警告の発火条件そのもの。参照が外れると、また黙ります。
    expect(SRC).toMatch(/isNearFreeLimit:\s*plan === 'free' && agentUsed >= 4/)
    expect(SRC).toMatch(/isAtFreeLimit:\s*plan === 'free' && agentUsed >= agentLimit/)
  })
})
