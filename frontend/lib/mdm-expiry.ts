import { AlertTriangle, Clock } from 'lucide-react'

// Mirrors server/internal/scheduler/mdm_credential_expiry_checker.go's
// expirySeverity thresholds so this badge and the alerts pipeline surface
// the same danger levels. Post-expiry and pre-expiry are computed on
// separate sides of zero to avoid Math.floor's negative-number drift
// (1 second after expiry previously rendered as "1日経過").
//
// Extracted to lib/ so the tier logic is unit-testable without mounting
// the React tree that embeds it.
export interface ExpiryBadge {
  label: string
  cls: string
  Icon: typeof AlertTriangle | typeof Clock
}

export function expiryBadge(expiryIso: string | null, now: Date = new Date()): ExpiryBadge | null {
  if (!expiryIso) return null
  const ms = new Date(expiryIso).getTime() - now.getTime()
  if (ms < 0) {
    const daysElapsed = Math.floor(-ms / 86_400_000)
    const label = daysElapsed === 0 ? '本日期限切れ' : `期限切れ (${daysElapsed}日経過)`
    return { label, cls: 'bg-red-500/20 text-red-300 border-red-500/40', Icon: AlertTriangle }
  }
  const daysLeft = Math.floor(ms / 86_400_000)
  if (daysLeft < 1) {
    return { label: '本日中に期限切れ', cls: 'bg-red-500/20 text-red-300 border-red-500/40', Icon: AlertTriangle }
  }
  if (daysLeft < 7) {
    return { label: `残り${daysLeft}日`, cls: 'bg-orange-500/20 text-orange-300 border-orange-500/40', Icon: AlertTriangle }
  }
  if (daysLeft < 30) {
    return { label: `残り${daysLeft}日`, cls: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30', Icon: Clock }
  }
  return { label: `残り${daysLeft}日`, cls: 'bg-gray-500/15 text-gray-400 border-gray-500/30', Icon: Clock }
}
