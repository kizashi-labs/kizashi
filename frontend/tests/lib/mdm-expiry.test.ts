import { describe, it, expect } from 'vitest'
import { AlertTriangle, Clock } from 'lucide-react'
import { expiryBadge } from '@/lib/mdm-expiry'

// Fixed clock so boundary math is deterministic across CI runs.
// 2026-04-19T12:00:00Z — noon in UTC to avoid day-rollover artifacts
// from either direction of local timezones the test may run in.
const NOW = new Date('2026-04-19T12:00:00Z')

// isoPlusDays builds an expiry timestamp `d` days from NOW. Accepts
// fractional days so we can target the < 1 day and the "1 second after
// expiry" edge cases without fighting with hours/seconds arithmetic.
function isoPlusDays(d: number): string {
  return new Date(NOW.getTime() + d * 86_400_000).toISOString()
}

describe('expiryBadge', () => {
  it('null 入力で null を返す', () => {
    expect(expiryBadge(null, NOW)).toBeNull()
  })

  // ─── Past-expiry branch ────────────────────────────────────────────────────

  it('期限切れ直後(1秒経過)は「本日期限切れ」を返す (daysElapsed=0)', () => {
    // This is the regression the extraction was meant to protect against:
    // Math.floor(-(-1sec) / 86400000) = Math.floor(1.15e-5) = 0, not 1.
    const iso = new Date(NOW.getTime() - 1000).toISOString()
    const b = expiryBadge(iso, NOW)
    expect(b?.label).toBe('本日期限切れ')
    expect(b?.cls).toContain('bg-red-500/20')
    expect(b?.Icon).toBe(AlertTriangle)
  })

  it('1日経過で "期限切れ (1日経過)" を返す', () => {
    const iso = isoPlusDays(-1)
    const b = expiryBadge(iso, NOW)
    expect(b?.label).toBe('期限切れ (1日経過)')
    expect(b?.Icon).toBe(AlertTriangle)
  })

  it('30日経過でも赤 tier のまま (post-expiry は常に red)', () => {
    const iso = isoPlusDays(-30)
    const b = expiryBadge(iso, NOW)
    expect(b?.label).toBe('期限切れ (30日経過)')
    expect(b?.cls).toContain('bg-red-500/20')
  })

  // ─── Pre-expiry severity ladder ────────────────────────────────────────────
  // Thresholds must match server/internal/scheduler/mdm_credential_expiry_checker.go's
  // expirySeverity (< 1 / < 7 / < 30). If either side moves without the other,
  // the UI badge and the alert severity diverge and operators see mismatched
  // urgency indicators.

  it('残り0.5日(12h)は "本日中に期限切れ" で赤 tier', () => {
    const iso = isoPlusDays(0.5)
    const b = expiryBadge(iso, NOW)
    expect(b?.label).toBe('本日中に期限切れ')
    expect(b?.cls).toContain('bg-red-500/20')
    expect(b?.Icon).toBe(AlertTriangle)
  })

  it('残り6日は orange tier', () => {
    const iso = isoPlusDays(6)
    const b = expiryBadge(iso, NOW)
    expect(b?.label).toBe('残り6日')
    expect(b?.cls).toContain('bg-orange-500/20')
    expect(b?.Icon).toBe(AlertTriangle)
  })

  it('残り7日は yellow tier (閾値の下側に落ちる)', () => {
    // 7 is the boundary: orange is < 7, so 7 itself is yellow.
    const iso = isoPlusDays(7)
    const b = expiryBadge(iso, NOW)
    expect(b?.label).toBe('残り7日')
    expect(b?.cls).toContain('bg-yellow-500/15')
    expect(b?.Icon).toBe(Clock)
  })

  it('残り29日は yellow tier', () => {
    const iso = isoPlusDays(29)
    const b = expiryBadge(iso, NOW)
    expect(b?.label).toBe('残り29日')
    expect(b?.cls).toContain('bg-yellow-500/15')
  })

  it('残り30日は muted tier (健康)', () => {
    // 30 is the boundary: yellow is < 30, so 30 itself is muted.
    const iso = isoPlusDays(30)
    const b = expiryBadge(iso, NOW)
    expect(b?.label).toBe('残り30日')
    expect(b?.cls).toContain('bg-gray-500/15')
    expect(b?.Icon).toBe(Clock)
  })

  it('残り365日でも muted tier のまま', () => {
    const iso = isoPlusDays(365)
    const b = expiryBadge(iso, NOW)
    expect(b?.label).toBe('残り365日')
    expect(b?.cls).toContain('bg-gray-500/15')
  })

  // ─── Default-parameter behavior ────────────────────────────────────────────

  it('now パラメータ省略時は現在時刻を使う(形式検証のみ)', () => {
    // Far-future expiry so we don't race the clock. The point is that
    // passing no second argument must not crash (i.e. the Date default
    // parameter resolves correctly).
    const iso = new Date(Date.now() + 365 * 86_400_000).toISOString()
    const b = expiryBadge(iso)
    expect(b).not.toBeNull()
    expect(b?.label).toMatch(/残り/)
  })
})
