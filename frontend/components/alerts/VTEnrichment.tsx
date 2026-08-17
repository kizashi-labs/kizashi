import { ExternalLink, AlertTriangle, ShieldCheck, ShieldAlert, HelpCircle } from 'lucide-react'
import { format, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'

// ─── 型定義 ───────────────────────────────────────────────────────────────────

export interface VTEnrichmentData {
  status?: string          // "clean" | "malicious" | "suspicious" | "unknown"
  score?: number           // malicious votes out of total
  total_engines?: number
  malicious_count?: number
  file_type?: string
  names?: string[]
  tags?: string[]
  first_seen?: string
  last_seen?: string
  error?: string
}

export interface VTEnrichmentProps {
  enrichment: VTEnrichmentData | null | undefined
}

// ─── ステータス設定 ───────────────────────────────────────────────────────────

type VTStatus = 'malicious' | 'suspicious' | 'clean' | 'unknown'

const STATUS_CONFIG: Record<VTStatus, {
  label: string
  icon: React.ReactNode
  badgeCls: string
  barCls: string
}> = {
  malicious: {
    label: '悪意あり',
    icon: <ShieldAlert className="w-3.5 h-3.5" />,
    badgeCls: 'bg-red-900/30 border-red-700/50 text-red-300',
    barCls: 'bg-red-500',
  },
  suspicious: {
    label: '疑わしい',
    icon: <AlertTriangle className="w-3.5 h-3.5" />,
    badgeCls: 'bg-orange-900/30 border-orange-700/50 text-orange-300',
    barCls: 'bg-orange-500',
  },
  clean: {
    label: 'クリーン',
    icon: <ShieldCheck className="w-3.5 h-3.5" />,
    badgeCls: 'bg-green-900/30 border-green-700/50 text-green-300',
    barCls: 'bg-green-500',
  },
  unknown: {
    label: '不明',
    icon: <HelpCircle className="w-3.5 h-3.5" />,
    badgeCls: 'bg-falcon-border border-[#2a3d5a] text-[#8899aa]',
    barCls: 'bg-falcon-subtle',
  },
}

function getStatusConfig(status?: string) {
  const key = (status ?? 'unknown') as VTStatus
  return STATUS_CONFIG[key] ?? STATUS_CONFIG.unknown
}

// ─── 日付フォーマット ─────────────────────────────────────────────────────────

function formatDate(iso?: string): string {
  if (!iso) return '—'
  try {
    return format(parseISO(iso), 'yyyy/MM/dd', { locale: ja })
  } catch {
    return iso
  }
}

// ─── コンポーネント ───────────────────────────────────────────────────────────

export function VTEnrichment({ enrichment }: VTEnrichmentProps) {
  if (!enrichment) return null

  // エラー状態
  if (enrichment.error) {
    return (
      <div className="rounded-lg border border-falcon-border bg-[#0d1623] p-3 space-y-1">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-[#8899aa] uppercase tracking-wide">
          <img src="/vt-logo.svg" alt="" className="w-3.5 h-3.5 opacity-40" />
          VirusTotal
        </div>
        <div className="flex items-center gap-1.5 text-xs text-red-300">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          {enrichment.error}
        </div>
      </div>
    )
  }

  const statusCfg = getStatusConfig(enrichment.status)
  const maliciousCount = enrichment.malicious_count ?? 0
  const totalEngines = enrichment.total_engines ?? 0
  const ratio = totalEngines > 0 ? maliciousCount / totalEngines : 0

  const visibleNames = (enrichment.names ?? []).slice(0, 3)
  const moreNames = (enrichment.names?.length ?? 0) - visibleNames.length

  return (
    <div className="rounded-lg border border-falcon-border bg-[#0d1623] p-3 space-y-3 text-xs">

      {/* ヘッダー行: VTロゴ + ステータスバッジ + リンク */}
      <div className="flex items-center justify-between gap-2">
        <span className="text-[#5a6a7a] font-semibold uppercase tracking-wide text-[10px]">
          VirusTotal
        </span>
        <div className="flex items-center gap-2 ml-auto">
          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[11px]
                            font-semibold ${statusCfg.badgeCls}`}>
            {statusCfg.icon}
            {statusCfg.label}
          </span>
          {/* リンク（プレースホルダー） */}
          <a
            href="#"
            className="inline-flex items-center gap-0.5 text-[#5a6a7a] hover:text-blue-400
                       transition-colors text-[10px]"
            onClick={e => e.preventDefault()}
          >
            <ExternalLink className="w-3 h-3" />
            VirusTotal で確認
          </a>
        </div>
      </div>

      {/* スコア + 検出バー */}
      {totalEngines > 0 && (
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-[#8899aa]">
              <span className={`font-bold ${maliciousCount > 0 ? 'text-red-300' : 'text-green-300'}`}>
                {maliciousCount}
              </span>
              <span className="text-[#5a6a7a]">/{totalEngines}</span>
              <span className="ml-1 text-[#5a6a7a]">エンジンが検出</span>
            </span>
            <span className="text-[#5a6a7a] font-mono">
              {(ratio * 100).toFixed(0)}%
            </span>
          </div>

          {/* 検出バー */}
          <div className="h-1.5 w-full bg-falcon-border rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${statusCfg.barCls}`}
              style={{ width: `${Math.max(ratio * 100, ratio > 0 ? 2 : 0)}%` }}
            />
          </div>
        </div>
      )}

      {/* メタ情報グリッド */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11px]">

        {/* ファイルタイプ */}
        {enrichment.file_type && (
          <>
            <span className="text-[#5a6a7a]">ファイル形式</span>
            <span className="text-[#c8d8e8] font-mono truncate">{enrichment.file_type}</span>
          </>
        )}

        {/* 初回検出 */}
        {enrichment.first_seen && (
          <>
            <span className="text-[#5a6a7a]">初回検出</span>
            <span className="text-[#c8d8e8]">{formatDate(enrichment.first_seen)}</span>
          </>
        )}

        {/* 最終検出 */}
        {enrichment.last_seen && (
          <>
            <span className="text-[#5a6a7a]">最終検出</span>
            <span className="text-[#c8d8e8]">{formatDate(enrichment.last_seen)}</span>
          </>
        )}
      </div>

      {/* ファイル名 */}
      {visibleNames.length > 0 && (
        <div className="space-y-1">
          <span className="text-[10px] text-[#5a6a7a] uppercase tracking-wide">関連ファイル名</span>
          <div className="space-y-0.5">
            {visibleNames.map((name, i) => (
              <div
                key={i}
                className="text-[11px] font-mono text-[#c8d8e8] truncate bg-falcon-bg
                           px-2 py-0.5 rounded"
                title={name}
              >
                {name}
              </div>
            ))}
            {moreNames > 0 && (
              <div className="text-[10px] text-[#5a6a7a] pl-2">
                他 {moreNames} 件...
              </div>
            )}
          </div>
        </div>
      )}

      {/* タグ */}
      {enrichment.tags && enrichment.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {enrichment.tags.map(tag => (
            <span
              key={tag}
              className="px-1.5 py-0.5 text-[10px] rounded bg-falcon-border text-falcon-muted
                         border border-[#2a3d5a]"
            >
              {tag}
            </span>
          ))}
        </div>
      )}

    </div>
  )
}
