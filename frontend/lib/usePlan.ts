'use client'

// オープンソース版のスタブ。
//
// 商用版では、この hook が /api/v1/admin/license からプランと利用可能機能を取得し、
// <PlanGate> がそれを見て画面を制限します。オープンソース版にはプランが存在せず、
// このリポジトリに含まれる機能はすべて利用できます。したがって:
//
//   - ライセンス API を呼びません（公開版にそのエンドポイントはありません）
//   - hasFeature / isAtLeast は常に true を返します
//   - エージェント数の上限はありません
//
// 呼び出し側を書き換えずに済むよう、型と戻り値の形は商用版と同一に保っています。

// Feature constants — mirror server/internal/license/license.go
export const Feature = {
  BasicDetection:  'basic_detection',
  Alerts:          'alerts',
  Reports:         'reports',

  AIInvestigation: 'ai_investigation',
  SIEM:            'siem_integration',
  Playbooks:       'playbooks',
  ThreatIntel:     'threat_intel',
  YARA:            'yara',
  MLDetection:     'ml_detection',
  ThreatHunting:   'threat_hunting',
  MultiTenant:     'multi_tenant',
  Compliance:      'compliance',
  APIAccess:       'api_access',
  XDR:             'xdr',
  Deception:       'deception',
  Forensics:       'forensics',
  SOAR:            'soar',
  MDM:             'mdm',
} as const

export type FeatureKey = typeof Feature[keyof typeof Feature]

export const Plan = {
  Lite:         'lite',
  Starter:      'starter',
  Professional: 'professional',
  Enterprise:   'enterprise',
} as const

export type PlanKey = typeof Plan[keyof typeof Plan]

interface UsePlanResult {
  plan: string | null
  features: string[]
  hasFeature: (feature: FeatureKey) => boolean
  isPlan: (plan: PlanKey) => boolean
  isAtLeast: (plan: PlanKey) => boolean
  isLoading: boolean
  daysRemaining: number
  isExpired: boolean
  agentLimit: number
  agentUsed: number
  isNearFreeLimit: boolean
  isAtFreeLimit: boolean
}

const ALL_FEATURES: string[] = Object.values(Feature)

export function usePlan(): UsePlanResult {
  return {
    plan: 'oss',
    features: ALL_FEATURES,
    hasFeature: () => true,
    isPlan: () => false,
    isAtLeast: () => true,
    isLoading: false,
    daysRemaining: -1,  // -1 は無期限を表すセンチネル
    isExpired: false,
    agentLimit: 0,      // 0 = 無制限
    agentUsed: 0,
    isNearFreeLimit: false,
    isAtFreeLimit: false,
  }
}
