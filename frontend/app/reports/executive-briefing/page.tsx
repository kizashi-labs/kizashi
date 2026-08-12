'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Briefcase, Download, Mail, Globe, Printer, X, Send,
  TrendingUp, TrendingDown, Minus, AlertTriangle, CheckCircle,
  Shield, Target, BarChart2, Clock, DollarSign, Award,
  ChevronRight, Calendar, Star, FileText,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type ClassificationLevel = 'confidential' | 'internal' | 'public'
type TrafficLight = 'RED' | 'AMBER' | 'GREEN'
type Language = 'ja' | 'en'
type Priority = 'high' | 'medium' | 'low'

interface KPICard {
  key: string
  label: string
  value: string | number
  unit: string
  trend: 'up' | 'down' | 'flat'
  trendValue: string
  trendDirection: 'good' | 'bad' | 'neutral'
  sub?: string
}

interface TopRisk {
  title: string
  business_impact: string
  mitigation_status: string
  owner: string
  severity: 'critical' | 'high' | 'medium'
}

interface Improvement {
  category: string
  description: string
  date: string
  impact: string
}

interface Recommendation {
  title: string
  description: string
  priority: Priority
  budget_impact: string
}

interface BriefingData {
  company_name: string
  period: string
  period_start: string
  period_end: string
  generated_at: string
  traffic_light: TrafficLight
  traffic_light_justification: string
  summary_bullets: string[]
  kpis: KPICard[]
  top_risks: TopRisk[]
  improvements: Improvement[]
  recommendations: Recommendation[]
  next_quarter_initiatives: string[]
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_BRIEFING_JA: BriefingData = {
  company_name: '株式会社サイバーシールド',
  period: '2026年 第1四半期',
  period_start: '2026-01-01',
  period_end: '2026-03-31',
  generated_at: '2026-03-18T12:00:00Z',
  traffic_light: 'AMBER',
  traffic_light_justification: 'セキュリティスコアは改善傾向にあるが、コンプライアンス達成率が目標に未達であり、2件の重大インシデントが発生した。全体的なリスク水準は管理可能な範囲だが、継続的な注意が必要。',
  summary_bullets: [
    'セキュリティスコアは前四半期比 +8% 向上し、82点に到達。AI検知エンジンの導入が主因。',
    '重大インシデント2件が発生。いずれも24時間以内に封じ込めに成功し、データ流出は確認されず。',
    'ゼロトラストアーキテクチャの第1フェーズを完了。対象システムの95%でMFAが有効化された。',
  ],
  kpis: [
    { key: 'security_score', label: 'セキュリティスコア', value: 82, unit: '点 / 100', trend: 'up', trendValue: '+8%', trendDirection: 'good', sub: '前四半期: 74点' },
    { key: 'critical_incidents', label: '重大インシデント件数', value: 2, unit: '件', trend: 'down', trendValue: '-3件', trendDirection: 'good', sub: '前四半期: 5件' },
    { key: 'mttr', label: '平均対応時間 (MTTR)', value: 6.8, unit: '時間', trend: 'down', trendValue: '-2.1h', trendDirection: 'good', sub: '目標: 4.0時間' },
    { key: 'compliance', label: 'コンプライアンス達成率', value: 87, unit: '%', trend: 'up', trendValue: '+5%', trendDirection: 'good', sub: 'ISO27001: 91% / SOC2: 83%' },
    { key: 'roi', label: 'セキュリティ投資ROI', value: '3.2×', unit: '', trend: 'up', trendValue: '+0.4×', trendDirection: 'good', sub: '侵害回避コスト: ¥480M' },
  ],
  top_risks: [
    { title: 'ランサムウェアによるサプライチェーン攻撃', business_impact: 'サードパーティ経由の侵入による業務停止。推定損失: ¥200M〜¥500M', mitigation_status: '対策進行中 (70%完了)', owner: '田中 太郎 (CISO)', severity: 'critical' },
    { title: 'クラウドインフラの設定ミス', business_impact: '誤設定によるデータ公開リスク。顧客データ保護規制違反の可能性', mitigation_status: 'CSPMツール導入済み、継続監視中', owner: '山田 次郎 (クラウドアーキテクト)', severity: 'high' },
    { title: 'AIシステムへの敵対的攻撃', business_impact: 'AI検知エンジンの欺瞞により脅威検知率が低下するリスク', mitigation_status: '研究・評価段階', owner: '佐藤 美咲 (セキュリティエンジニア)', severity: 'medium' },
  ],
  improvements: [
    { category: 'インフラ', description: 'ゼロトラストアーキテクチャ Phase 1 完了 — 全主要サービスにmTLS実装', date: '2026-02-15', impact: 'ラテラルムーブメントリスク 65% 削減' },
    { category: '脅威検知', description: 'AI検知エンジン v2.0 導入 — 検知率 94% → 97% に向上', date: '2026-01-28', impact: '誤検知率 40% 削減、アナリスト工数 30% 削減' },
    { category: 'コンプライアンス', description: 'SOC 2 Type II 監査完了 — 初回取得成功', date: '2026-03-10', impact: '顧客信頼度向上、契約獲得に貢献' },
    { category: '教育', description: 'セキュリティ意識向上訓練を全社展開 — 参加率 98%', date: '2026-02-01', impact: 'フィッシング被害件数 55% 削減' },
    { category: 'インシデント対応', description: 'SOARプレイブック 12本追加 — 自動対応カバレッジ 70%→82% に拡大', date: '2026-03-05', impact: '平均対応時間 2.1時間短縮' },
  ],
  recommendations: [
    { title: 'ゼロトラスト Phase 2 の即時推進', description: 'レガシーシステムおよびOTネットワークへのゼロトラスト適用を優先的に推進。現状の侵害リスクを大幅に低減できる。', priority: 'high', budget_impact: '¥85M (Q2-Q3)' },
    { title: 'サプライチェーンセキュリティプログラムの確立', description: '重要なサードパーティに対するセキュリティ評価フレームワークを策定し、定期的な監査を実施する体制を構築する。', priority: 'high', budget_impact: '¥30M (年間)' },
    { title: 'セキュリティオペレーションセンターの24×7体制強化', description: '現在の業務時間外のカバレッジギャップを解消するため、MSSP（マネージドセキュリティサービス）との契約を検討する。', priority: 'medium', budget_impact: '¥60M (年間)' },
  ],
  next_quarter_initiatives: [
    'ゼロトラスト Phase 2: OTネットワーク・レガシーシステム対応',
    'サプライチェーンリスク評価フレームワーク構築・主要ベンダー評価実施',
    'SIEM/SOAR統合強化 — アラート相関分析精度向上',
    'インシデント対応訓練の全規模実施 (Q2 Q2サプライチェーン攻撃シミュレーション)',
    'クラウドセキュリティポスチャ管理 (CSPM) の全リージョン展開',
  ],
}

const MOCK_BRIEFING_EN: BriefingData = {
  company_name: 'CyberShield Corporation',
  period: 'Q1 2026',
  period_start: '2026-01-01',
  period_end: '2026-03-31',
  generated_at: '2026-03-18T12:00:00Z',
  traffic_light: 'AMBER',
  traffic_light_justification: 'Security posture is improving but compliance targets were not fully met, and 2 critical incidents occurred. Overall risk is within manageable bounds but requires continued attention.',
  summary_bullets: [
    'Security score improved +8% QoQ to reach 82/100, primarily driven by the AI detection engine deployment.',
    '2 critical incidents occurred, both contained within 24 hours. No confirmed data exfiltration.',
    'Zero Trust Architecture Phase 1 completed — MFA enabled on 95% of targeted systems.',
  ],
  kpis: [
    { key: 'security_score', label: 'Security Score', value: 82, unit: '/ 100', trend: 'up', trendValue: '+8%', trendDirection: 'good', sub: 'Previous: 74' },
    { key: 'critical_incidents', label: 'Critical Incidents', value: 2, unit: '', trend: 'down', trendValue: '-3', trendDirection: 'good', sub: 'Previous quarter: 5' },
    { key: 'mttr', label: 'MTTR (Mean Time to Respond)', value: 6.8, unit: 'hrs', trend: 'down', trendValue: '-2.1h', trendDirection: 'good', sub: 'Target: 4.0 hrs' },
    { key: 'compliance', label: 'Compliance Achievement', value: 87, unit: '%', trend: 'up', trendValue: '+5%', trendDirection: 'good', sub: 'ISO27001: 91% / SOC2: 83%' },
    { key: 'roi', label: 'Security ROI', value: '3.2×', unit: '', trend: 'up', trendValue: '+0.4×', trendDirection: 'good', sub: 'Breach avoidance value: $3.2M' },
  ],
  top_risks: [
    { title: 'Ransomware via Supply Chain Attack', business_impact: 'Third-party compromise leading to operational disruption. Estimated loss: $1.5M–$4M', mitigation_status: 'Mitigation in progress (70% complete)', owner: 'Taro Tanaka (CISO)', severity: 'critical' },
    { title: 'Cloud Infrastructure Misconfiguration', business_impact: 'Data exposure risk from misconfigurations; potential regulatory violations', mitigation_status: 'CSPM tool deployed, continuous monitoring active', owner: 'Jiro Yamada (Cloud Architect)', severity: 'high' },
    { title: 'Adversarial Attacks on AI Systems', business_impact: 'Risk of reduced detection efficacy through AI model evasion', mitigation_status: 'Research and evaluation phase', owner: 'Misaki Sato (Security Engineer)', severity: 'medium' },
  ],
  improvements: [
    { category: 'Infrastructure', description: 'Zero Trust Phase 1 complete — mTLS implemented across all core services', date: '2026-02-15', impact: '65% reduction in lateral movement risk' },
    { category: 'Threat Detection', description: 'AI detection engine v2.0 deployed — detection rate improved from 94% to 97%', date: '2026-01-28', impact: '40% fewer false positives, 30% analyst workload reduction' },
    { category: 'Compliance', description: 'SOC 2 Type II audit completed — first-time certification achieved', date: '2026-03-10', impact: 'Enhanced customer trust, contributing to contract wins' },
    { category: 'Training', description: 'Company-wide security awareness training — 98% participation rate', date: '2026-02-01', impact: '55% reduction in phishing incidents' },
    { category: 'Incident Response', description: '12 new SOAR playbooks — automated response coverage expanded from 70% to 82%', date: '2026-03-05', impact: 'MTTR reduced by 2.1 hours' },
  ],
  recommendations: [
    { title: 'Accelerate Zero Trust Phase 2', description: 'Prioritize extending zero trust to legacy systems and OT networks to significantly reduce current breach risk.', priority: 'high', budget_impact: '$650K (Q2-Q3)' },
    { title: 'Establish Supply Chain Security Program', description: 'Develop a security assessment framework for critical third parties with regular audit cadence.', priority: 'high', budget_impact: '$230K (annual)' },
    { title: 'Strengthen 24×7 SOC Coverage', description: 'Evaluate MSSP engagement to close after-hours coverage gaps in the current SOC model.', priority: 'medium', budget_impact: '$460K (annual)' },
  ],
  next_quarter_initiatives: [
    'Zero Trust Phase 2: OT network and legacy system coverage',
    'Supply chain risk assessment framework — evaluate top 20 vendors',
    'SIEM/SOAR integration enhancement for improved alert correlation',
    'Full-scale incident response drill (Q2 Supply Chain Attack simulation)',
    'CSPM rollout to all cloud regions and accounts',
  ],
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CLASSIFICATION_BADGE: Record<ClassificationLevel, string> = {
  confidential: 'bg-red-500/20 text-red-400 border border-red-500/40',
  internal: 'bg-orange-500/20 text-orange-400 border border-orange-500/40',
  public: 'bg-green-500/20 text-green-400 border border-green-500/40',
}
const CLASSIFICATION_LABEL: Record<ClassificationLevel, string> = {
  confidential: '機密 / CONFIDENTIAL',
  internal: '社内限定 / INTERNAL',
  public: '公開 / PUBLIC',
}

const TRAFFIC_LIGHT_CONFIG: Record<TrafficLight, { color: string; bg: string; border: string; label: string; labelEn: string }> = {
  GREEN: { color: 'text-green-400', bg: 'bg-green-500', border: 'border-green-500', label: '良好', labelEn: 'GOOD' },
  AMBER: { color: 'text-yellow-400', bg: 'bg-yellow-500', border: 'border-yellow-500', label: '要注意', labelEn: 'CAUTION' },
  RED: { color: 'text-red-400', bg: 'bg-red-500', border: 'border-red-500', label: '危険', labelEn: 'CRITICAL' },
}

const PRIORITY_BADGE: Record<Priority, string> = {
  high: 'bg-red-500/10 text-red-400 border border-red-500/30',
  medium: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
  low: 'bg-green-500/10 text-green-400 border border-green-500/30',
}
const PRIORITY_LABEL_JA: Record<Priority, string> = { high: '高', medium: '中', low: '低' }

const SEVERITY_BADGE: Record<'critical' | 'high' | 'medium', string> = {
  critical: 'bg-red-500/10 text-red-400 border border-red-500/30',
  high: 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
  medium: 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30',
}
const SEVERITY_LABEL_JA: Record<'critical' | 'high' | 'medium', string> = { critical: '重大', high: '高', medium: '中' }

const IMPROVEMENT_CATEGORY_COLOR: Record<string, string> = {
  'インフラ': 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
  '脅威検知': 'bg-purple-500/10 text-purple-400 border border-purple-500/30',
  'コンプライアンス': 'bg-green-500/10 text-green-400 border border-green-500/30',
  '教育': 'bg-teal-500/10 text-teal-400 border border-teal-500/30',
  'インシデント対応': 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
  'Infrastructure': 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
  'Threat Detection': 'bg-purple-500/10 text-purple-400 border border-purple-500/30',
  'Compliance': 'bg-green-500/10 text-green-400 border border-green-500/30',
  'Training': 'bg-teal-500/10 text-teal-400 border border-teal-500/30',
  'Incident Response': 'bg-orange-500/10 text-orange-400 border border-orange-500/30',
}

function TrendIcon({ trend, direction }: { trend: 'up' | 'down' | 'flat'; direction: 'good' | 'bad' | 'neutral' }) {
  const colorMap = { good: 'text-green-400', bad: 'text-red-400', neutral: 'text-[#7d92b0]' }
  const color = colorMap[direction]
  if (trend === 'up') return <TrendingUp className={`w-4 h-4 ${color}`} />
  if (trend === 'down') return <TrendingDown className={`w-4 h-4 ${color}`} />
  return <Minus className={`w-4 h-4 ${color}`} />
}

// ─── Email Modal ──────────────────────────────────────────────────────────────

function EmailModal({ onClose, onSend }: { onClose: () => void; onSend: (recipients: string[]) => void }) {
  const [recipients, setRecipients] = useState<string[]>(['ceo@company.com', 'cto@company.com'])
  const [input, setInput] = useState('')

  const addRecipient = () => {
    if (input && !recipients.includes(input)) {
      setRecipients(r => [...r, input])
      setInput('')
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold text-lg">メールで送信</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white p-1 rounded hover:bg-[#1e2d42] transition-colors"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-[#7d92b0] text-sm mb-1.5">送信先</label>
            <div className="flex gap-2 mb-2">
              <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addRecipient() } }} placeholder="email@example.com" className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
              <button onClick={addRecipient} className="px-3 py-2 bg-[#1e2d42] text-white rounded-lg text-sm hover:bg-[#243347] transition-colors">追加</button>
            </div>
            <div className="flex flex-wrap gap-2">
              {recipients.map(r => (
                <span key={r} className="flex items-center gap-1 px-2 py-1 bg-[#1e2d42] rounded text-xs text-white">
                  {r}<button onClick={() => setRecipients(rr => rr.filter(x => x !== r))} className="text-[#7d92b0] hover:text-[#e8002d] ml-1"><X className="w-3 h-3" /></button>
                </span>
              ))}
            </div>
          </div>
          <p className="text-[#7d92b0] text-xs">ブリーフィングはPDF形式で添付され送信されます。</p>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-[#7d92b0] text-sm hover:text-white rounded-lg hover:bg-[#1e2d42] transition-colors">キャンセル</button>
          <button onClick={() => { onSend(recipients); onClose() }} className="px-4 py-2 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors flex items-center gap-2">
            <Send className="w-4 h-4" />送信
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Briefing Preview ─────────────────────────────────────────────────────────

interface BriefingPreviewProps {
  briefing: BriefingData
  classification: ClassificationLevel
  lang: Language
}

function BriefingPreview({ briefing, classification, lang }: BriefingPreviewProps) {
  const tlConfig = TRAFFIC_LIGHT_CONFIG[briefing.traffic_light]
  const isJa = lang === 'ja'

  return (
    <div className="bg-white rounded-xl shadow-2xl overflow-hidden" id="briefing-preview">
      {/* Cover Page */}
      <div className="bg-[#070d19] text-white p-12 text-center relative">
        <div className="absolute top-4 right-4">
          <span className={`px-3 py-1 rounded text-xs font-bold uppercase ${CLASSIFICATION_BADGE[classification]}`}>
            {CLASSIFICATION_LABEL[classification]}
          </span>
        </div>
        <div className="w-16 h-16 rounded-full bg-[#e8002d] flex items-center justify-center mx-auto mb-6">
          <Shield className="w-8 h-8 text-white" />
        </div>
        <h1 className="text-3xl font-bold mb-2">{briefing.company_name}</h1>
        <p className="text-[#7d92b0] text-sm mb-6 uppercase tracking-widest">
          {isJa ? 'セキュリティブリーフィング' : 'SECURITY BRIEFING'}
        </p>
        <div className="inline-block border border-[#1e2d42] rounded-lg px-6 py-3 bg-[#0d1220]">
          <p className="text-white font-semibold text-xl">{briefing.period}</p>
          <p className="text-[#7d92b0] text-sm mt-1">{briefing.period_start} — {briefing.period_end}</p>
        </div>
        <p className="text-[#3d5068] text-xs mt-6">{isJa ? '生成日' : 'Generated'}: {new Date(briefing.generated_at).toLocaleDateString(isJa ? 'ja-JP' : 'en-US')}</p>
      </div>

      <div className="p-8 space-y-8 bg-gray-50">
        {/* Executive Summary */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <h2 className="text-gray-900 font-bold text-xl mb-4 pb-2 border-b border-gray-100 flex items-center gap-2">
            <Star className="w-5 h-5 text-[#e8002d]" />
            {isJa ? 'エグゼクティブサマリー' : 'Executive Summary'}
          </h2>
          <ul className="space-y-3 mb-6">
            {briefing.summary_bullets.map((b, i) => (
              <li key={i} className="flex items-start gap-3 text-gray-700 text-sm">
                <ChevronRight className="w-4 h-4 text-[#e8002d] flex-shrink-0 mt-0.5" />
                <span>{b}</span>
              </li>
            ))}
          </ul>
          {/* Traffic Light */}
          <div className={`flex items-start gap-4 p-4 rounded-lg border ${tlConfig.border} bg-opacity-10`} style={{ backgroundColor: briefing.traffic_light === 'GREEN' ? '#dcfce7' : briefing.traffic_light === 'AMBER' ? '#fef9c3' : '#fee2e2' }}>
            <div className={`w-12 h-12 rounded-full ${tlConfig.bg} flex items-center justify-center flex-shrink-0 shadow-md`}>
              <span className="text-white font-bold text-xs">{briefing.traffic_light}</span>
            </div>
            <div>
              <p className={`font-bold text-lg ${tlConfig.color}`}>{isJa ? `総合判定: ${tlConfig.label}` : `Overall Status: ${tlConfig.labelEn}`}</p>
              <p className="text-gray-600 text-sm mt-1">{briefing.traffic_light_justification}</p>
            </div>
          </div>
        </section>

        {/* KPIs */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <h2 className="text-gray-900 font-bold text-xl mb-4 pb-2 border-b border-gray-100 flex items-center gap-2">
            <BarChart2 className="w-5 h-5 text-[#e8002d]" />
            {isJa ? '主要KPI (Board Metrics)' : 'Key Performance Indicators'}
          </h2>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
            {briefing.kpis.map(kpi => (
              <div key={kpi.key} className="bg-gray-50 rounded-xl p-4 border border-gray-100">
                <p className="text-gray-500 text-xs font-medium mb-2">{kpi.label}</p>
                <div className="flex items-end gap-2 mb-1">
                  <p className="text-gray-900 font-bold text-3xl">{kpi.value}</p>
                  <p className="text-gray-500 text-sm mb-1">{kpi.unit}</p>
                </div>
                <div className="flex items-center gap-1 mb-2">
                  <TrendIcon trend={kpi.trend} direction={kpi.trendDirection} />
                  <span className={`text-sm font-medium ${kpi.trendDirection === 'good' ? 'text-green-600' : kpi.trendDirection === 'bad' ? 'text-red-600' : 'text-gray-500'}`}>{kpi.trendValue}</span>
                </div>
                {kpi.sub && <p className="text-gray-400 text-xs">{kpi.sub}</p>}
              </div>
            ))}
          </div>
        </section>

        {/* Top Risks */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <h2 className="text-gray-900 font-bold text-xl mb-4 pb-2 border-b border-gray-100 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-500" />
            {isJa ? '重大リスク Top 3' : 'Top 3 Critical Risks'}
          </h2>
          <div className="space-y-4">
            {briefing.top_risks.map((risk, i) => (
              <div key={i} className="p-4 rounded-lg border border-gray-100 bg-gray-50">
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-gray-500 font-bold text-sm w-6">#{i + 1}</span>
                    <h3 className="text-gray-900 font-semibold text-sm">{risk.title}</h3>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium flex-shrink-0 ${SEVERITY_BADGE[risk.severity]}`}>
                    {isJa ? SEVERITY_LABEL_JA[risk.severity] : risk.severity.toUpperCase()}
                  </span>
                </div>
                <p className="text-gray-600 text-sm mb-2 ml-8">{risk.business_impact}</p>
                <div className="ml-8 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-gray-500">
                    <CheckCircle className="w-3.5 h-3.5 text-green-500" />
                    <span>{risk.mitigation_status}</span>
                  </div>
                  <div className="flex items-center gap-1 text-xs text-gray-400">
                    <span>{isJa ? 'オーナー:' : 'Owner:'}</span>
                    <span className="text-gray-600 font-medium">{risk.owner}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Improvements */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <h2 className="text-gray-900 font-bold text-xl mb-4 pb-2 border-b border-gray-100 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-green-500" />
            {isJa ? '今期の改善点' : 'This Period Improvements'}
          </h2>
          <div className="space-y-3">
            {briefing.improvements.map((imp, i) => (
              <div key={i} className="flex items-start gap-4">
                <span className="text-gray-400 text-xs w-20 flex-shrink-0 mt-1">{imp.date.slice(5).replace('-', '/')}</span>
                <span className={`px-2 py-0.5 rounded text-xs font-medium flex-shrink-0 ${IMPROVEMENT_CATEGORY_COLOR[imp.category] ?? 'bg-gray-100 text-gray-600'}`}>{imp.category}</span>
                <div className="flex-1">
                  <p className="text-gray-800 text-sm">{imp.description}</p>
                  <p className="text-green-600 text-xs mt-0.5">{imp.impact}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Recommendations */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <h2 className="text-gray-900 font-bold text-xl mb-4 pb-2 border-b border-gray-100 flex items-center gap-2">
            <Target className="w-5 h-5 text-blue-500" />
            {isJa ? '推奨事項' : 'Strategic Recommendations'}
          </h2>
          <div className="space-y-4">
            {briefing.recommendations.map((rec, i) => (
              <div key={i} className="p-4 rounded-lg border border-gray-100 bg-gray-50">
                <div className="flex items-start justify-between gap-3 mb-2">
                  <h3 className="text-gray-900 font-semibold text-sm">{rec.title}</h3>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium flex-shrink-0 ${PRIORITY_BADGE[rec.priority]}`}>
                    {isJa ? `優先度: ${PRIORITY_LABEL_JA[rec.priority]}` : `Priority: ${rec.priority.toUpperCase()}`}
                  </span>
                </div>
                <p className="text-gray-600 text-sm mb-2">{rec.description}</p>
                <div className="flex items-center gap-2 text-xs text-gray-500">
                  <DollarSign className="w-3.5 h-3.5" />
                  <span>{isJa ? '予算インパクト:' : 'Budget Impact:'} <span className="font-medium text-gray-700">{rec.budget_impact}</span></span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Next Quarter */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <h2 className="text-gray-900 font-bold text-xl mb-4 pb-2 border-b border-gray-100 flex items-center gap-2">
            <Calendar className="w-5 h-5 text-purple-500" />
            {isJa ? '次期計画' : 'Next Quarter Initiatives'}
          </h2>
          <ul className="space-y-2">
            {briefing.next_quarter_initiatives.map((init, i) => (
              <li key={i} className="flex items-start gap-3 text-gray-700 text-sm">
                <span className="w-5 h-5 rounded-full bg-purple-100 text-purple-600 text-xs font-bold flex items-center justify-center flex-shrink-0 mt-0.5">{i + 1}</span>
                <span>{init}</span>
              </li>
            ))}
          </ul>
        </section>

        {/* Footer */}
        <div className="flex items-center justify-between pt-4 border-t border-gray-200">
          <p className="text-gray-400 text-xs">{CLASSIFICATION_LABEL[classification]}</p>
          <p className="text-gray-400 text-xs">{briefing.company_name} — {briefing.period}</p>
          <p className="text-gray-400 text-xs">{isJa ? '生成日' : 'Generated'}: {new Date(briefing.generated_at).toLocaleDateString(isJa ? 'ja-JP' : 'en-US')}</p>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ExecutiveBriefingPage() {
  const [lang, setLang] = useState<Language>('ja')
  const [classification, setClassification] = useState<ClassificationLevel>('confidential')
  const [period, setPeriod] = useState('2026-Q1')
  const [generated, setGenerated] = useState(false)
  const [showEmailModal, setShowEmailModal] = useState(false)
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)

  const showToast = (message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 3500)
  }

  const briefing = lang === 'ja' ? MOCK_BRIEFING_JA : MOCK_BRIEFING_EN

  const handleGenerate = () => {
    setGenerated(true)
    showToast(lang === 'ja' ? 'ブリーフィングを生成しました' : 'Briefing generated successfully')
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {toast && (
        <div className={`fixed top-6 right-6 z-50 flex items-center gap-2 px-4 py-3 rounded-lg shadow-xl border text-sm font-medium ${toast.type === 'success' ? 'bg-green-500/10 border-green-500/30 text-green-400' : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
          {toast.type === 'success' ? <CheckCircle className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          {toast.message}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#0d1220] border border-[#1e2d42] flex items-center justify-center">
            <Briefcase className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">経営層向けブリーフィング生成</h1>
            <p className="text-[#7d92b0] text-sm">取締役会・経営幹部向けセキュリティサマリーの生成</p>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 mb-6">
        <div className="flex flex-wrap items-center gap-4">
          {/* Period */}
          <div>
            <label className="block text-[#7d92b0] text-xs mb-1.5">期間</label>
            <select value={period} onChange={e => setPeriod(e.target.value)} className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
              <option value="2026-Q1">2026年 Q1 (1月〜3月)</option>
              <option value="2025-Q4">2025年 Q4 (10月〜12月)</option>
              <option value="2025-Q3">2025年 Q3 (7月〜9月)</option>
              <option value="2025-Q2">2025年 Q2 (4月〜6月)</option>
            </select>
          </div>

          {/* Classification */}
          <div>
            <label className="block text-[#7d92b0] text-xs mb-1.5">機密レベル</label>
            <select value={classification} onChange={e => setClassification(e.target.value as ClassificationLevel)} className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
              <option value="confidential">機密 / Confidential</option>
              <option value="internal">社内限定 / Internal</option>
              <option value="public">公開 / Public</option>
            </select>
          </div>

          {/* Language Toggle */}
          <div>
            <label className="block text-[#7d92b0] text-xs mb-1.5">言語</label>
            <div className="flex gap-1 bg-[#070d19] border border-[#1e2d42] rounded-lg p-1">
              {(['ja', 'en'] as Language[]).map(l => (
                <button key={l} onClick={() => setLang(l)} className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${lang === l ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'}`}>
                  {l === 'ja' ? '日本語' : 'English'}
                </button>
              ))}
            </div>
          </div>

          {/* Generate Button */}
          <div className="ml-auto flex items-end gap-3">
            <button onClick={handleGenerate} className="flex items-center gap-2 px-5 py-2.5 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors">
              <FileText className="w-4 h-4" />
              ブリーフィングを生成
            </button>
          </div>
        </div>

        {/* Export Controls (shown after generation) */}
        {generated && (
          <div className="flex items-center gap-3 mt-4 pt-4 border-t border-[#1e2d42]">
            <span className="text-[#7d92b0] text-xs">エクスポート:</span>
            <button onClick={() => showToast(lang === 'ja' ? 'PDF出力を開始しました' : 'PDF export started')} className="flex items-center gap-2 px-3 py-2 bg-[#070d19] border border-[#1e2d42] text-white text-sm rounded-lg hover:bg-[#1e2d42] transition-colors">
              <Printer className="w-4 h-4 text-red-400" />PDFでエクスポート
            </button>
            <button onClick={() => showToast(lang === 'ja' ? 'PowerPoint出力を開始しました' : 'PowerPoint export started')} className="flex items-center gap-2 px-3 py-2 bg-[#070d19] border border-[#1e2d42] text-white text-sm rounded-lg hover:bg-[#1e2d42] transition-colors">
              <Download className="w-4 h-4 text-orange-400" />PowerPointで書き出し
            </button>
            <button onClick={() => setShowEmailModal(true)} className="flex items-center gap-2 px-3 py-2 bg-[#070d19] border border-[#1e2d42] text-white text-sm rounded-lg hover:bg-[#1e2d42] transition-colors">
              <Mail className="w-4 h-4 text-blue-400" />メールで送信
            </button>
          </div>
        )}
      </div>

      {/* Briefing Preview */}
      {generated ? (
        <BriefingPreview briefing={briefing} classification={classification} lang={lang} />
      ) : (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-16 text-center">
          <div className="w-16 h-16 rounded-full bg-[#070d19] border border-[#1e2d42] flex items-center justify-center mx-auto mb-4">
            <Briefcase className="w-8 h-8 text-[#3d5068]" />
          </div>
          <p className="text-white font-semibold text-lg mb-2">ブリーフィングを生成してください</p>
          <p className="text-[#7d92b0] text-sm mb-6">期間・機密レベル・言語を選択し、「ブリーフィングを生成」ボタンをクリックしてください。</p>
          <button onClick={handleGenerate} className="flex items-center gap-2 px-5 py-2.5 bg-[#e8002d] text-white text-sm font-medium rounded-lg hover:bg-[#c0001f] transition-colors mx-auto">
            <FileText className="w-4 h-4" />ブリーフィングを生成
          </button>
        </div>
      )}

      {/* Email Modal */}
      {showEmailModal && (
        <EmailModal onClose={() => setShowEmailModal(false)} onSend={(recipients) => { showToast(`${recipients.length}名に送信しました`) }} />
      )}
    </div>
  )
}
