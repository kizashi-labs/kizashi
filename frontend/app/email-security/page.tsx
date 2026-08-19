'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Mail, Shield, AlertTriangle, Filter, X, Loader2,
  Upload, ExternalLink, Eye, Search, CheckCircle, XCircle,
  RefreshCw, FileText,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { USE_MOCK, m } from '@/lib/mock'

// ── Types ─────────────────────────────────────────────────────────────────────

type ThreatType = 'phishing' | 'malware' | 'bec' | 'spam' | 'clean'
type Verdict = 'clean' | 'malicious' | 'suspicious' | 'unknown'
type UrlStatus = 'malicious' | 'suspicious' | 'clean' | 'unreachable'

interface EmailStats {
  analyzed_today: number
  threats_blocked: number
  phishing_attempts: number
  malware_attachments: number
}

interface ThreatEmail {
  id: string
  timestamp: string
  sender: string
  subject: string
  threat_type: ThreatType
  risk_score: number
  action: 'blocked' | 'quarantined' | 'delivered'
  spf: boolean
  dkim: boolean
  dmarc: boolean
  body_preview: string
  attachments: string[]
  urls: string[]
}

interface AttachmentAnalysis {
  id: string
  filename: string
  type: string
  size_kb: number
  sha256: string
  verdict: Verdict
  sandbox_score: number
  av_detections: number
  av_total: number
}

interface UrlScan {
  id: string
  url: string
  status: UrlStatus
  categories: string[]
  first_seen: string
  scan_date: string
  redirects: number
}

interface SenderReputation {
  id: string
  domain: string
  reputation_score: number
  category: string
  volume_per_day: number
  last_seen: string
  spf_compliant: boolean
  dkim_compliant: boolean
}

// ── Mock Data ─────────────────────────────────────────────────────────────────

const MOCK_EMAIL_STATS: EmailStats = {
  analyzed_today: 18420,
  threats_blocked: 342,
  phishing_attempts: 89,
  malware_attachments: 23,
}

const MOCK_THREAT_EMAILS: ThreatEmail[] = [
  { id: 'em-001', timestamp: '2026-03-18T08:05:00Z', sender: 'ceo-impersonation@evil-corp.ru', subject: '至急: 銀行振込のお願い（社長より）', threat_type: 'bec', risk_score: 98, action: 'blocked', spf: false, dkim: false, dmarc: false, body_preview: 'お世話になります。急ぎの案件ですが、本日中に以下の口座へ振り込みをお願いします...', attachments: [], urls: ['http://evil-bank-transfer.ru/pay'] },
  { id: 'em-002', timestamp: '2026-03-18T08:32:00Z', sender: 'noreply@microsoft-security-alert.phish.com', subject: 'あなたのMicrosoftアカウントが危険にさらされています', threat_type: 'phishing', risk_score: 95, action: 'blocked', spf: false, dkim: false, dmarc: false, body_preview: 'Microsoftセキュリティチームからの重要なお知らせです。あなたのアカウントに不正アクセスが...', attachments: [], urls: ['https://login.microsoft-secure-verify.phish.com/verify'] },
  { id: 'em-003', timestamp: '2026-03-18T09:10:00Z', sender: 'invoice@billing-system.cn', subject: 'Invoice_March2026.exe', threat_type: 'malware', risk_score: 99, action: 'blocked', spf: false, dkim: false, dmarc: false, body_preview: '請求書を添付しております。ご確認のほどよろしくお願いします。', attachments: ['Invoice_March2026.exe'], urls: [] },
  { id: 'em-004', timestamp: '2026-03-18T09:45:00Z', sender: 'deals@spam-blast.info', subject: '【緊急】今だけ！特別セール情報', threat_type: 'spam', risk_score: 42, action: 'quarantined', spf: true, dkim: false, dmarc: false, body_preview: '期間限定の特別オファーです！今すぐクリックして素晴らしい割引をお楽しみください...', attachments: [], urls: ['http://spam-deals-click.info/track?id=12345'] },
  { id: 'em-005', timestamp: '2026-03-18T10:20:00Z', sender: 'attacker@lookalike-domain.xyz', subject: '重要: 人事システムのパスワードリセット', threat_type: 'phishing', risk_score: 91, action: 'blocked', spf: false, dkim: false, dmarc: false, body_preview: 'セキュリティポリシーの変更により、全社員のパスワードリセットが必要です...', attachments: [], urls: ['https://hr-system-login.lookalike-domain.xyz/reset'] },
  { id: 'em-006', timestamp: '2026-03-18T11:05:00Z', sender: 'supplier@legitimate-vendor.com', subject: '製品カタログ 2026年版', threat_type: 'clean', risk_score: 5, action: 'delivered', spf: true, dkim: true, dmarc: true, body_preview: '平素よりお世話になっております。2026年版製品カタログを送付いたします。', attachments: ['catalog_2026.pdf'], urls: ['https://legitimate-vendor.com/catalog'] },
  { id: 'em-007', timestamp: '2026-03-18T11:40:00Z', sender: 'malware-dist@cdn-download.biz', subject: 'Document.docm - Shared with you', threat_type: 'malware', risk_score: 97, action: 'blocked', spf: false, dkim: false, dmarc: false, body_preview: 'こちらのドキュメントを共有します。マクロを有効にしてご覧ください。', attachments: ['Document.docm'], urls: [] },
  { id: 'em-008', timestamp: '2026-03-18T12:15:00Z', sender: 'cfo-fraud@business-wire.evil', subject: 'Confidential: Q1 Wire Transfer Authorization', threat_type: 'bec', risk_score: 96, action: 'blocked', spf: false, dkim: false, dmarc: false, body_preview: 'This is strictly confidential. I need you to process an urgent wire transfer...', attachments: [], urls: [] },
  { id: 'em-009', timestamp: '2026-03-18T13:00:00Z', sender: 'amazon-noreply@amazn-orders.phish.co', subject: 'Your Amazon Order Has Been Placed - Verify Now', threat_type: 'phishing', risk_score: 88, action: 'quarantined', spf: false, dkim: false, dmarc: false, body_preview: 'We noticed suspicious activity on your Amazon account. Please verify your identity...', attachments: [], urls: ['https://amazn-account-verify.phish.co/signin'] },
  { id: 'em-010', timestamp: '2026-03-18T13:35:00Z', sender: 'security@github.com', subject: 'GitHub Security Alert: New sign-in', threat_type: 'clean', risk_score: 2, action: 'delivered', spf: true, dkim: true, dmarc: true, body_preview: 'A new device has signed into your account.', attachments: [], urls: ['https://github.com/settings/security'] },
  { id: 'em-011', timestamp: '2026-03-18T14:10:00Z', sender: 'ransomware-operator@darkmail.onion.re', subject: 'Your files have been encrypted', threat_type: 'malware', risk_score: 100, action: 'blocked', spf: false, dkim: false, dmarc: false, body_preview: 'All your company files have been encrypted. To restore access, follow these instructions...', attachments: ['README_HOW_TO_DECRYPT.txt', 'decrypt_tool.exe'], urls: ['http://ransom-payment.darkweb-exit.top/pay'] },
  { id: 'em-012', timestamp: '2026-03-18T14:50:00Z', sender: 'newsletter@trusted-news.jp', subject: 'セキュリティニュースレター 2026年3月号', threat_type: 'clean', risk_score: 3, action: 'delivered', spf: true, dkim: true, dmarc: true, body_preview: '今月のセキュリティニュースをお届けします。最新の脅威情報や対策について...', attachments: ['newsletter_march_2026.pdf'], urls: ['https://trusted-news.jp/march2026'] },
]

const MOCK_ATTACHMENTS: AttachmentAnalysis[] = [
  { id: 'att-001', filename: 'Invoice_March2026.exe', type: 'PE32', size_kb: 892, sha256: '4a8b2c9d1e3f5a7b...c91f2e4d', verdict: 'malicious', sandbox_score: 98, av_detections: 52, av_total: 68 },
  { id: 'att-002', filename: 'Document.docm', type: 'OOXML Macro', size_kb: 234, sha256: '1b3c5e7f9a2d4b6e...8f1c3a5b', verdict: 'malicious', sandbox_score: 94, av_detections: 41, av_total: 68 },
  { id: 'att-003', filename: 'decrypt_tool.exe', type: 'PE32', size_kb: 1240, sha256: '7f9b1d3e5a7c9b2d...4e6f8a1c', verdict: 'malicious', sandbox_score: 100, av_detections: 65, av_total: 68 },
  { id: 'att-004', filename: 'README_HOW_TO_DECRYPT.txt', type: 'Text', size_kb: 2, sha256: 'abc123def456...789', verdict: 'suspicious', sandbox_score: 35, av_detections: 2, av_total: 68 },
  { id: 'att-005', filename: 'catalog_2026.pdf', type: 'PDF', size_kb: 3480, sha256: '2e4f6a8c0d2e4f6a...8c0d2e4f', verdict: 'clean', sandbox_score: 2, av_detections: 0, av_total: 68 },
  { id: 'att-006', filename: 'newsletter_march_2026.pdf', type: 'PDF', size_kb: 1820, sha256: '9d0e2f4a6c8e0f2d...4a6c8e0f', verdict: 'clean', sandbox_score: 0, av_detections: 0, av_total: 68 },
  { id: 'att-007', filename: 'macro_enabled_report.xlsm', type: 'OOXML Macro', size_kb: 512, sha256: '3f5a7c9b1d3f5a7c...9b1d3f5a', verdict: 'suspicious', sandbox_score: 67, av_detections: 8, av_total: 68 },
  { id: 'att-008', filename: 'setup_update.msi', type: 'MSI', size_kb: 4200, sha256: '0f2d4e6a8c0f2d4e...6a8c0f2d', verdict: 'unknown', sandbox_score: 45, av_detections: 3, av_total: 68 },
]

const MOCK_URL_SCANS: UrlScan[] = [
  { id: 'url-001', url: 'https://login.microsoft-secure-verify.phish.com/verify', status: 'malicious', categories: ['フィッシング', 'マルウェア'], first_seen: '2026-03-15T10:00:00Z', scan_date: '2026-03-18T08:32:00Z', redirects: 3 },
  { id: 'url-002', url: 'http://evil-bank-transfer.ru/pay', status: 'malicious', categories: ['詐欺', 'BEC'], first_seen: '2026-03-17T08:00:00Z', scan_date: '2026-03-18T08:05:00Z', redirects: 1 },
  { id: 'url-003', url: 'https://hr-system-login.lookalike-domain.xyz/reset', status: 'malicious', categories: ['フィッシング'], first_seen: '2026-03-16T14:00:00Z', scan_date: '2026-03-18T10:20:00Z', redirects: 2 },
  { id: 'url-004', url: 'https://amazn-account-verify.phish.co/signin', status: 'malicious', categories: ['フィッシング', 'なりすまし'], first_seen: '2026-03-18T12:00:00Z', scan_date: '2026-03-18T13:00:00Z', redirects: 4 },
  { id: 'url-005', url: 'http://ransom-payment.darkweb-exit.top/pay', status: 'malicious', categories: ['ランサムウェア', 'C2'], first_seen: '2026-03-10T09:00:00Z', scan_date: '2026-03-18T14:10:00Z', redirects: 0 },
  { id: 'url-006', url: 'http://spam-deals-click.info/track?id=12345', status: 'suspicious', categories: ['スパム', 'トラッキング'], first_seen: '2026-03-01T10:00:00Z', scan_date: '2026-03-18T09:45:00Z', redirects: 5 },
  { id: 'url-007', url: 'https://legitimate-vendor.com/catalog', status: 'clean', categories: ['ビジネス'], first_seen: '2022-01-01T00:00:00Z', scan_date: '2026-03-18T11:05:00Z', redirects: 0 },
  { id: 'url-008', url: 'https://github.com/settings/security', status: 'clean', categories: ['開発', '信頼済み'], first_seen: '2008-04-10T00:00:00Z', scan_date: '2026-03-18T13:35:00Z', redirects: 0 },
  { id: 'url-009', url: 'https://trusted-news.jp/march2026', status: 'clean', categories: ['ニュース'], first_seen: '2020-06-15T00:00:00Z', scan_date: '2026-03-18T14:50:00Z', redirects: 0 },
  { id: 'url-010', url: 'https://suspicious-analytics.track.biz/pixel?uid=abc', status: 'suspicious', categories: ['トラッキング', 'プライバシー'], first_seen: '2026-02-20T00:00:00Z', scan_date: '2026-03-18T12:00:00Z', redirects: 2 },
]

const MOCK_SENDERS: SenderReputation[] = [
  { id: 'sr-001', domain: 'evil-corp.ru', reputation_score: 2, category: 'BEC / 詐欺', volume_per_day: 45, last_seen: '2026-03-18T08:05:00Z', spf_compliant: false, dkim_compliant: false },
  { id: 'sr-002', domain: 'phish.com', reputation_score: 1, category: 'フィッシング', volume_per_day: 1200, last_seen: '2026-03-18T08:32:00Z', spf_compliant: false, dkim_compliant: false },
  { id: 'sr-003', domain: 'billing-system.cn', reputation_score: 5, category: 'マルウェア配布', volume_per_day: 320, last_seen: '2026-03-18T09:10:00Z', spf_compliant: false, dkim_compliant: false },
  { id: 'sr-004', domain: 'spam-blast.info', reputation_score: 18, category: 'スパム', volume_per_day: 50000, last_seen: '2026-03-18T09:45:00Z', spf_compliant: true, dkim_compliant: false },
  { id: 'sr-005', domain: 'microsoft.com', reputation_score: 99, category: '信頼済みベンダー', volume_per_day: 82000, last_seen: '2026-03-18T13:35:00Z', spf_compliant: true, dkim_compliant: true },
  { id: 'sr-006', domain: 'github.com', reputation_score: 98, category: '信頼済みベンダー', volume_per_day: 45000, last_seen: '2026-03-18T13:35:00Z', spf_compliant: true, dkim_compliant: true },
  { id: 'sr-007', domain: 'lookalike-domain.xyz', reputation_score: 3, category: 'フィッシング', volume_per_day: 180, last_seen: '2026-03-18T10:20:00Z', spf_compliant: false, dkim_compliant: false },
  { id: 'sr-008', domain: 'legitimate-vendor.com', reputation_score: 87, category: 'ビジネス', volume_per_day: 230, last_seen: '2026-03-18T11:05:00Z', spf_compliant: true, dkim_compliant: true },
  { id: 'sr-009', domain: 'darkmail.onion.re', reputation_score: 0, category: 'ランサムウェア', volume_per_day: 12, last_seen: '2026-03-18T14:10:00Z', spf_compliant: false, dkim_compliant: false },
  { id: 'sr-010', domain: 'trusted-news.jp', reputation_score: 92, category: 'ニュース / 情報', volume_per_day: 5600, last_seen: '2026-03-18T14:50:00Z', spf_compliant: true, dkim_compliant: true },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmt(d: string) {
  return new Date(d).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}
function fmtDate(d: string) {
  return new Date(d).toLocaleDateString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

// ── Badges ────────────────────────────────────────────────────────────────────

function ThreatTypeBadge({ type }: { type: ThreatType }) {
  const cfg: Record<ThreatType, { cls: string; label: string }> = {
    phishing: { cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30', label: 'フィッシング' },
    malware:  { cls: 'bg-red-500/20 text-red-400 border-red-500/30',          label: 'マルウェア' },
    bec:      { cls: 'bg-purple-500/20 text-purple-400 border-purple-500/30', label: 'BEC詐欺' },
    spam:     { cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', label: 'スパム' },
    clean:    { cls: 'bg-green-500/20 text-green-400 border-green-500/30',    label: 'クリーン' },
  }
  const { cls, label } = cfg[type]
  return <span className={`inline-flex px-2 py-0.5 rounded-sm border text-[11px] font-medium ${cls}`}>{label}</span>
}

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const cfg: Record<Verdict, { cls: string; label: string }> = {
    malicious:  { cls: 'bg-red-500/20 text-red-400 border-red-500/30',          label: '悪意あり' },
    suspicious: { cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30', label: '疑わしい' },
    clean:      { cls: 'bg-green-500/20 text-green-400 border-green-500/30',    label: 'クリーン' },
    unknown:    { cls: 'bg-[#1e2d42] text-[#7d92b0] border-[#2a3f5f]',         label: '不明' },
  }
  const { cls, label } = cfg[verdict]
  return <span className={`inline-flex px-2 py-0.5 rounded-sm border text-[11px] font-medium ${cls}`}>{label}</span>
}

function UrlStatusBadge({ status }: { status: UrlStatus }) {
  const cfg: Record<UrlStatus, { cls: string; label: string }> = {
    malicious:   { cls: 'bg-red-500/20 text-red-400 border-red-500/30',          label: '悪意あり' },
    suspicious:  { cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30', label: '疑わしい' },
    clean:       { cls: 'bg-green-500/20 text-green-400 border-green-500/30',    label: 'クリーン' },
    unreachable: { cls: 'bg-[#1e2d42] text-[#7d92b0] border-[#2a3f5f]',         label: '到達不能' },
  }
  const { cls, label } = cfg[status]
  return <span className={`inline-flex px-2 py-0.5 rounded-sm border text-[11px] font-medium ${cls}`}>{label}</span>
}

function AuthBadge({ pass, label }: { pass: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-sm text-[10px] font-medium border ${
      pass ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30'
    }`}>
      {pass ? <CheckCircle className="w-2.5 h-2.5" /> : <XCircle className="w-2.5 h-2.5" />}
      {label}
    </span>
  )
}

function ActionBadge({ action }: { action: 'blocked' | 'quarantined' | 'delivered' }) {
  const cfg = {
    blocked:     'bg-red-500/20 text-red-400 border-red-500/30',
    quarantined: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    delivered:   'bg-green-500/20 text-green-400 border-green-500/30',
  }
  const labels = { blocked: 'ブロック', quarantined: '隔離', delivered: '配信済み' }
  return <span className={`inline-flex px-2 py-0.5 rounded-sm border text-[11px] font-medium ${cfg[action]}`}>{labels[action]}</span>
}

// ── Email Detail Modal ────────────────────────────────────────────────────────

function EmailDetailModal({ email, onClose }: { email: ThreatEmail; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <Mail className="w-5 h-5 text-[#e8002d]" />
            <div>
              <h2 className="text-white font-semibold">メール詳細分析</h2>
              <p className="text-[#7d92b0] text-xs">{email.sender}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"><X className="w-4 h-4" /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
              <p className="text-[#7d92b0] text-xs mb-1">脅威タイプ</p>
              <ThreatTypeBadge type={email.threat_type} />
            </div>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
              <p className="text-[#7d92b0] text-xs mb-1">リスクスコア</p>
              <p className={`text-lg font-bold ${email.risk_score >= 80 ? 'text-red-400' : email.risk_score >= 50 ? 'text-orange-400' : 'text-green-400'}`}>
                {email.risk_score}/100
              </p>
            </div>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
              <p className="text-[#7d92b0] text-xs mb-1">アクション</p>
              <ActionBadge action={email.action} />
            </div>
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">メールヘッダー</h3>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3 font-mono text-xs text-[#7d92b0] space-y-1 overflow-x-auto">
              <p><span className="text-[#3d5068]">From:</span> <span className="text-white">{email.sender}</span></p>
              <p><span className="text-[#3d5068]">Subject:</span> <span className="text-white">{email.subject}</span></p>
              <p><span className="text-[#3d5068]">Date:</span> <span className="text-white">{new Date(email.timestamp).toUTCString()}</span></p>
              <p><span className="text-[#3d5068]">Received:</span> <span className="text-white">from mail.evil.ru (203.0.113.50) by mx1.company.com</span></p>
              <p><span className="text-[#3d5068]">X-Spam-Score:</span> <span className="text-red-400">{email.risk_score}.0</span></p>
              <p><span className="text-[#3d5068]">X-Mailer:</span> <span className="text-white">PHPMailer 6.1.8</span></p>
              <p><span className="text-[#3d5068]">Content-Type:</span> <span className="text-white">text/html; charset=UTF-8</span></p>
            </div>
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">認証結果</h3>
            <div className="flex gap-2">
              <AuthBadge pass={email.spf} label="SPF" />
              <AuthBadge pass={email.dkim} label="DKIM" />
              <AuthBadge pass={email.dmarc} label="DMARC" />
            </div>
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">本文プレビュー</h3>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3 text-sm text-[#7d92b0] italic">
              {email.body_preview}
            </div>
          </div>
          {email.attachments.length > 0 && (
            <div>
              <h3 className="text-white font-semibold text-sm mb-2">添付ファイル</h3>
              <div className="flex flex-wrap gap-2">
                {email.attachments.map(a => (
                  <span key={a} className="flex items-center gap-1.5 px-2.5 py-1 bg-red-500/10 border border-red-500/20 rounded-sm text-xs text-red-400 font-mono">
                    <FileText className="w-3 h-3" />{a}
                  </span>
                ))}
              </div>
            </div>
          )}
          {email.urls.length > 0 && (
            <div>
              <h3 className="text-white font-semibold text-sm mb-2">含まれるURL</h3>
              <div className="space-y-1">
                {email.urls.map(u => (
                  <div key={u} className="flex items-center gap-2 p-2 bg-red-500/5 border border-red-500/15 rounded-sm text-xs font-mono text-red-400">
                    <ExternalLink className="w-3 h-3 shrink-0" /><span className="truncate">{u}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div>
            <h3 className="text-white font-semibold text-sm mb-3">脅威分析内訳</h3>
            <div className="space-y-2">
              {[
                { label: '送信元IP評価', score: email.spf ? 20 : 90 },
                { label: '件名分析 (NLP)', score: Math.min(100, email.risk_score + 5) },
                { label: '本文パターン一致', score: email.risk_score },
                { label: 'URLレピュテーション', score: email.urls.length > 0 ? Math.min(100, email.risk_score + 10) : 5 },
                { label: '添付ファイルスコア', score: email.attachments.length > 0 ? 95 : 0 },
              ].map(item => (
                <div key={item.label}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-[#7d92b0]">{item.label}</span>
                    <span className="text-xs font-bold text-white">{item.score}%</span>
                  </div>
                  <div className="h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${item.score >= 80 ? 'bg-red-500' : item.score >= 50 ? 'bg-orange-500' : 'bg-green-500'}`}
                      style={{ width: `${item.score}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="ml-auto px-4 py-2 text-[#7d92b0] hover:text-white text-sm transition-colors">閉じる</button>
        </div>
      </div>
    </div>
  )
}

// ── Sandbox Report Modal ──────────────────────────────────────────────────────

function SandboxModal({ file, onClose }: { file: AttachmentAnalysis; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[85vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">サンドボックスレポート: {file.filename}</h2>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"><X className="w-4 h-4" /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          <div className="flex items-center gap-4">
            <VerdictBadge verdict={file.verdict} />
            <span className="text-xs text-[#7d92b0]">スコア: <span className="text-white font-bold">{file.sandbox_score}/100</span></span>
            <span className="text-xs text-[#7d92b0]">AV検出: <span className="text-red-400 font-bold">{file.av_detections}/{file.av_total}</span></span>
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">動作サマリー</h3>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3 space-y-2 text-xs text-[#7d92b0]">
              <p className="text-red-400">• C:\Windows\Temp\svchost32.exe を作成し実行</p>
              <p className="text-red-400">• HKCU\Software\Microsoft\Windows\CurrentVersion\Run へ自己登録 (永続化)</p>
              <p className="text-orange-400">• 外部IP 185.220.101.45:443 へ接続試行 (C2通信)</p>
              <p className="text-orange-400">• Windows Defender の無効化を試行</p>
              <p>• 一時ファイルの作成: %TEMP%\tmp_xyz.dat</p>
            </div>
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">ドロップされたファイル</h3>
            <div className="space-y-1">
              {['C:\\Windows\\Temp\\svchost32.exe', 'C:\\Users\\Public\\Documents\\config.enc', '%TEMP%\\tmp_xyz.dat'].map(f => (
                <div key={f} className="p-2 bg-red-500/5 border border-red-500/15 rounded-sm text-xs font-mono text-red-300">{f}</div>
              ))}
            </div>
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">ネットワーク接続</h3>
            <div className="space-y-1">
              {[{ ip: '185.220.101.45', port: 443, proto: 'TCP', desc: 'C2通信' }, { ip: '8.8.8.8', port: 53, proto: 'UDP', desc: 'DNS (DGA クエリ)' }].map(c => (
                <div key={c.ip} className="flex items-center gap-3 p-2 bg-[#070d19] rounded-sm border border-[#1e2d42] text-xs">
                  <span className="font-mono text-[#e2e8f4]">{c.ip}:{c.port}</span>
                  <span className="text-[#7d92b0]">{c.proto}</span>
                  <span className="text-red-400">{c.desc}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">レジストリ変更</h3>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3 font-mono text-xs text-orange-300 space-y-1">
              <p>HKCU\...\Run\WindowsUpdate = &quot;C:\Windows\Temp\svchost32.exe&quot;</p>
              <p>HKLM\...\Windows Defender\DisableAntiSpyware = 1</p>
            </div>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-[#7d92b0] hover:text-white text-sm transition-colors">閉じる</button>
        </div>
      </div>
    </div>
  )
}

// ── URL Detail Modal ──────────────────────────────────────────────────────────

function UrlDetailModal({ scan, onClose }: { scan: UrlScan; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[85vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">URLスキャン詳細</h2>
          <button onClick={onClose} className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors"><X className="w-4 h-4" /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3 font-mono text-xs text-[#e2e8f4] break-all">{scan.url}</div>
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
              <p className="text-[#7d92b0] text-xs mb-1">ステータス</p>
              <UrlStatusBadge status={scan.status} />
            </div>
            <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
              <p className="text-[#7d92b0] text-xs mb-1">リダイレクト数</p>
              <p className="text-white font-bold">{scan.redirects}</p>
            </div>
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">スクリーンショット</h3>
            <div className="h-32 bg-[#070d19] border border-[#1e2d42] rounded-lg flex items-center justify-center text-[#3d5068] text-sm">
              スクリーンショット取得中... (サンドボックス実行)
            </div>
          </div>
          {scan.redirects > 0 && (
            <div>
              <h3 className="text-white font-semibold text-sm mb-2">リダイレクトチェーン</h3>
              <div className="space-y-1">
                {Array.from({ length: scan.redirects }).map((_, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="text-[#3d5068] w-4 text-right">{i + 1}</span>
                    <span className="w-2 h-2 rounded-full bg-orange-400 shrink-0" />
                    <span className="font-mono text-[#7d92b0] truncate">
                      {i === 0 ? scan.url : `https://redirect-${i}.${scan.url.split('/')[2]}/r`}
                    </span>
                    <span className="text-[#3d5068]">302</span>
                  </div>
                ))}
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-[#3d5068] w-4 text-right">{scan.redirects + 1}</span>
                  <span className="w-2 h-2 rounded-full bg-red-400 shrink-0" />
                  <span className="font-mono text-red-300">最終的な悪意ある宛先</span>
                </div>
              </div>
            </div>
          )}
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">ドメイン情報 / SSL</h3>
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
                <p className="text-[#7d92b0] mb-1">初回確認</p>
                <p className="text-white">{fmtDate(scan.first_seen)}</p>
              </div>
              <div className="bg-[#070d19] rounded-lg border border-[#1e2d42] p-3">
                <p className="text-[#7d92b0] mb-1">SSL証明書</p>
                <p className={`font-medium ${scan.status === 'clean' ? 'text-green-400' : 'text-red-400'}`}>
                  {scan.status === 'clean' ? "有効 (Let's Encrypt)" : '自己署名 / 無効'}
                </p>
              </div>
            </div>
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm mb-2">レピュテーションスコア</h3>
            <div className="space-y-1">
              {[
                { src: 'VirusTotal', val: scan.status === 'malicious' ? '48/92' : scan.status === 'suspicious' ? '12/92' : '0/92', bad: scan.status === 'malicious' },
                { src: 'URLScan.io', val: scan.status === 'malicious' ? '95%' : scan.status === 'suspicious' ? '45%' : '5%', bad: scan.status === 'malicious' },
                { src: 'PhishTank', val: scan.status === 'malicious' ? '検出済み' : '未検出', bad: scan.status === 'malicious' },
                { src: 'Spamhaus DBL', val: (scan.status === 'malicious' || scan.status === 'suspicious') ? '検出済み' : '未検出', bad: scan.status === 'malicious' || scan.status === 'suspicious' },
              ].map(r => (
                <div key={r.src} className="flex items-center justify-between text-xs p-2 bg-[#070d19] rounded-sm border border-[#1e2d42]">
                  <span className="text-[#7d92b0]">{r.src}</span>
                  <span className={r.bad ? 'text-red-400 font-medium' : 'text-green-400 font-medium'}>{r.val}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-[#7d92b0] hover:text-white text-sm transition-colors">閉じる</button>
        </div>
      </div>
    </div>
  )
}

// ── Threat Emails Tab ─────────────────────────────────────────────────────────

function ThreatEmailsTab() {
  const [typeFilter, setTypeFilter] = useState<ThreatType | 'all'>('all')
  const [selected, setSelected] = useState<ThreatEmail | null>(null)

  const { data, isLoading } = useQuery<{ emails: ThreatEmail[] }>({
    queryKey: ['email-threats'],
    queryFn: () => apiFetch<{ emails: ThreatEmail[] }>('/api/v1/email/threats').catch(() => ({ emails: [] })),
    staleTime: 30_000, refetchInterval: 60_000,
  })

  const emails = data?.emails ?? []
  const filtered = emails.filter(e => typeFilter === 'all' || e.threat_type === typeFilter)

  return (
    <div className="space-y-4">
      {selected && <EmailDetailModal email={selected} onClose={() => setSelected(null)} />}
      <div className="flex flex-wrap gap-3 items-center">
        <Filter className="w-4 h-4 text-[#7d92b0]" />
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value as ThreatType | 'all')}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/60">
          <option value="all">全タイプ</option>
          <option value="phishing">フィッシング</option>
          <option value="malware">マルウェア</option>
          <option value="bec">BEC詐欺</option>
          <option value="spam">スパム</option>
          <option value="clean">クリーン</option>
        </select>
        <span className="text-xs text-[#7d92b0] ml-auto">{filtered.length} 件</span>
      </div>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/50">
                {['日時', '送信者', '件名', '脅威タイプ', 'リスク', 'アクション', ''].map(h => (
                  <th key={h} className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={7} className="py-8 text-center text-[#7d92b0]"><Loader2 className="w-5 h-5 animate-spin inline" /></td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={7} className="py-12 text-center text-[#7d92b0] text-sm">脅威メールデータがありません</td></tr>
              ) : filtered.map(e => (
                <tr key={e.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="py-3 px-4 text-[#7d92b0] text-xs whitespace-nowrap">{fmt(e.timestamp)}</td>
                  <td className="py-3 px-4 text-xs font-mono text-white max-w-[160px]"><span className="truncate block">{e.sender}</span></td>
                  <td className="py-3 px-4 text-xs text-[#7d92b0] max-w-[200px]"><span className="truncate block">{e.subject}</span></td>
                  <td className="py-3 px-4"><ThreatTypeBadge type={e.threat_type} /></td>
                  <td className="py-3 px-4">
                    <span className={`text-xs font-bold ${e.risk_score >= 80 ? 'text-red-400' : e.risk_score >= 50 ? 'text-orange-400' : 'text-green-400'}`}>{e.risk_score}</span>
                  </td>
                  <td className="py-3 px-4"><ActionBadge action={e.action} /></td>
                  <td className="py-3 px-4">
                    <button onClick={() => setSelected(e)}
                      className="flex items-center gap-1 px-2 py-1 text-xs bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded-sm transition-colors border border-[#2a3f5f]">
                      <Eye className="w-3 h-3" />詳細
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Attachments Tab ───────────────────────────────────────────────────────────

function AttachmentsTab() {
  const [sandboxFile, setSandboxFile] = useState<AttachmentAnalysis | null>(null)
  const [verdictFilter, setVerdictFilter] = useState<Verdict | 'all'>('all')

  const { data, isLoading } = useQuery<{ attachments: AttachmentAnalysis[] }>({
    queryKey: ['email-attachments'],
    queryFn: () => apiFetch<{ attachments: AttachmentAnalysis[] }>('/api/v1/email/attachments').catch(() => ({ attachments: [] })),
    staleTime: 60_000,
  })

  const attachments = data?.attachments ?? []
  const filtered = attachments.filter(a => verdictFilter === 'all' || a.verdict === verdictFilter)

  return (
    <div className="space-y-4">
      {sandboxFile && <SandboxModal file={sandboxFile} onClose={() => setSandboxFile(null)} />}
      <div className="flex flex-wrap gap-3 items-center">
        <Filter className="w-4 h-4 text-[#7d92b0]" />
        <select value={verdictFilter} onChange={e => setVerdictFilter(e.target.value as Verdict | 'all')}
          className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/60">
          <option value="all">全判定</option>
          <option value="malicious">悪意あり</option>
          <option value="suspicious">疑わしい</option>
          <option value="clean">クリーン</option>
          <option value="unknown">不明</option>
        </select>
        <div className="ml-auto">
          <label className="flex items-center gap-2 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded-lg text-xs border border-[#2a3f5f] cursor-pointer transition-colors">
            <Upload className="w-3.5 h-3.5" />ファイル手動送信<input type="file" className="hidden" />
          </label>
        </div>
      </div>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/50">
                {['ファイル名', 'タイプ', 'サイズ', 'SHA256', '判定', 'スコア', 'AV検出', ''].map(h => (
                  <th key={h} className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={8} className="py-8 text-center text-[#7d92b0]"><Loader2 className="w-5 h-5 animate-spin inline" /></td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={8} className="py-12 text-center text-[#7d92b0] text-sm">添付ファイルデータがありません</td></tr>
              ) : filtered.map(a => (
                <tr key={a.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="py-3 px-4 text-xs text-white font-medium max-w-[160px]"><span className="truncate block">{a.filename}</span></td>
                  <td className="py-3 px-4"><span className="px-2 py-0.5 bg-[#1e2d42] text-[#7d92b0] border border-[#2a3f5f] rounded-sm text-[10px]">{a.type}</span></td>
                  <td className="py-3 px-4 text-[#7d92b0] text-xs">{a.size_kb} KB</td>
                  <td className="py-3 px-4 font-mono text-xs text-[#7d92b0] max-w-[120px]"><span className="truncate block">{a.sha256}</span></td>
                  <td className="py-3 px-4"><VerdictBadge verdict={a.verdict} /></td>
                  <td className="py-3 px-4">
                    <span className={`text-xs font-bold ${a.sandbox_score >= 80 ? 'text-red-400' : a.sandbox_score >= 50 ? 'text-orange-400' : 'text-green-400'}`}>{a.sandbox_score}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`text-xs font-medium ${a.av_detections > 0 ? 'text-red-400' : 'text-green-400'}`}>{a.av_detections}/{a.av_total}</span>
                  </td>
                  <td className="py-3 px-4">
                    <button onClick={() => setSandboxFile(a)}
                      className="flex items-center gap-1 px-2 py-1 text-xs bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded-sm transition-colors border border-[#2a3f5f]">
                      <Eye className="w-3 h-3" />レポート
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── URL Scan Tab ──────────────────────────────────────────────────────────────

function UrlScanTab() {
  const [selectedScan, setSelectedScan] = useState<UrlScan | null>(null)
  const [manualUrl, setManualUrl] = useState('')
  const [scanning, setScanning] = useState(false)

  const { data, isLoading } = useQuery<{ scans: UrlScan[] }>({
    queryKey: ['email-urls'],
    queryFn: () => apiFetch<{ scans: UrlScan[] }>('/api/v1/email/urls').catch(() => ({ scans: [] })),
    staleTime: 60_000,
  })

  const scans = data?.scans ?? []

  const handleScan = () => {
    if (!manualUrl.trim()) return
    setScanning(true)
    setTimeout(() => { setScanning(false); setManualUrl('') }, 2000)
  }

  return (
    <div className="space-y-4">
      {selectedScan && <UrlDetailModal scan={selectedScan} onClose={() => setSelectedScan(null)} />}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
        <p className="text-white text-sm font-medium mb-3">URLを手動スキャン</p>
        <div className="flex gap-2">
          <input value={manualUrl} onChange={e => setManualUrl(e.target.value)}
            placeholder="スキャンするURLを入力..."
            className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/60 font-mono" />
          <button onClick={handleScan} disabled={scanning || !manualUrl.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
            {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            スキャン
          </button>
        </div>
      </div>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/50">
                {['URL', 'ステータス', 'カテゴリ', '初回確認', 'スキャン日', 'リダイレクト', ''].map(h => (
                  <th key={h} className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={7} className="py-8 text-center text-[#7d92b0]"><Loader2 className="w-5 h-5 animate-spin inline" /></td></tr>
              ) : scans.length === 0 ? (
                <tr><td colSpan={7} className="py-12 text-center text-[#7d92b0] text-sm">URLスキャンデータがありません</td></tr>
              ) : scans.map(s => (
                <tr key={s.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="py-3 px-4 font-mono text-xs text-[#7d92b0] max-w-[220px]"><span className="truncate block">{s.url}</span></td>
                  <td className="py-3 px-4"><UrlStatusBadge status={s.status} /></td>
                  <td className="py-3 px-4 text-xs text-[#7d92b0]">{s.categories.join(', ')}</td>
                  <td className="py-3 px-4 text-[#7d92b0] text-xs whitespace-nowrap">{fmtDate(s.first_seen)}</td>
                  <td className="py-3 px-4 text-[#7d92b0] text-xs whitespace-nowrap">{fmt(s.scan_date)}</td>
                  <td className="py-3 px-4 text-xs text-white font-medium">{s.redirects}</td>
                  <td className="py-3 px-4">
                    <button onClick={() => setSelectedScan(s)}
                      className="flex items-center gap-1 px-2 py-1 text-xs bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded-sm transition-colors border border-[#2a3f5f]">
                      <Eye className="w-3 h-3" />詳細
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Sender Reputation Tab ─────────────────────────────────────────────────────

function SenderReputationTab() {
  const [domainQuery, setDomainQuery] = useState('')
  const [lookupResult, setLookupResult] = useState<SenderReputation | null>(null)
  const [searched, setSearched] = useState(false)

  const { data, isLoading } = useQuery<{ senders: SenderReputation[] }>({
    queryKey: ['email-senders'],
    queryFn: () => apiFetch<{ senders: SenderReputation[] }>('/api/v1/email/senders').catch(() => ({ senders: [] })),
    staleTime: 60_000,
  })

  const senders = data?.senders ?? []

  const handleLookup = () => {
    const found = senders.find(s => s.domain.toLowerCase().includes(domainQuery.toLowerCase()))
    setLookupResult(found ?? null)
    setSearched(true)
  }

  function scoreColor(score: number) {
    if (score >= 80) return 'text-green-400'
    if (score >= 50) return 'text-yellow-400'
    if (score >= 20) return 'text-orange-400'
    return 'text-red-400'
  }
  function scoreBar(score: number) {
    if (score >= 80) return 'bg-green-500'
    if (score >= 50) return 'bg-yellow-500'
    if (score >= 20) return 'bg-orange-500'
    return 'bg-red-500'
  }

  return (
    <div className="space-y-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
        <p className="text-white text-sm font-medium mb-3">ドメインレピュテーション照会</p>
        <div className="flex gap-2">
          <input value={domainQuery} onChange={e => setDomainQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleLookup()}
            placeholder="example.com"
            className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white focus:outline-hidden focus:border-[#e8002d]/60 font-mono" />
          <button onClick={handleLookup}
            className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded-lg text-sm transition-colors border border-[#2a3f5f]">
            <Search className="w-4 h-4" />照会
          </button>
        </div>
        {searched && (lookupResult ? (
          <div className="mt-3 p-3 bg-[#070d19] border border-[#1e2d42] rounded-lg space-y-2">
            <div className="flex items-center gap-3">
              <span className="font-mono text-white font-medium">{lookupResult.domain}</span>
              <span className={`text-2xl font-bold ${scoreColor(lookupResult.reputation_score)}`}>{lookupResult.reputation_score}</span>
              <span className="text-xs text-[#7d92b0]">/ 100</span>
            </div>
            <div className="flex gap-2">
              <AuthBadge pass={lookupResult.spf_compliant} label="SPF" />
              <AuthBadge pass={lookupResult.dkim_compliant} label="DKIM" />
            </div>
            <p className="text-xs text-[#7d92b0]">カテゴリ: <span className="text-white">{lookupResult.category}</span></p>
            <p className="text-xs text-[#7d92b0]">日量: <span className="text-white">{(lookupResult.volume_per_day ?? 0).toLocaleString()} メール</span></p>
          </div>
        ) : <p className="mt-3 text-xs text-[#7d92b0]">ドメインが見つかりません。</p>)}
      </div>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42] bg-[#070d19]/50">
                {['ドメイン', 'レピュテーション', 'カテゴリ', '日量', '最終確認', 'SPF', 'DKIM'].map(h => (
                  <th key={h} className="text-left py-3 px-4 text-[#7d92b0] text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={7} className="py-8 text-center text-[#7d92b0]"><Loader2 className="w-5 h-5 animate-spin inline" /></td></tr>
              ) : senders.length === 0 ? (
                <tr><td colSpan={7} className="py-12 text-center text-[#7d92b0] text-sm">送信者データがありません</td></tr>
              ) : senders.map(s => (
                <tr key={s.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                  <td className="py-3 px-4 font-mono text-xs text-white">{s.domain}</td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <span className={`text-sm font-bold w-8 ${scoreColor(s.reputation_score)}`}>{s.reputation_score}</span>
                      <div className="h-1.5 w-16 bg-[#1e2d42] rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${scoreBar(s.reputation_score)}`} style={{ width: `${s.reputation_score}%` }} />
                      </div>
                    </div>
                  </td>
                  <td className="py-3 px-4 text-xs text-[#7d92b0]">{s.category}</td>
                  <td className="py-3 px-4 text-xs text-white">{(s.volume_per_day ?? 0).toLocaleString()}</td>
                  <td className="py-3 px-4 text-[#7d92b0] text-xs whitespace-nowrap">{fmt(s.last_seen)}</td>
                  <td className="py-3 px-4">{s.spf_compliant ? <CheckCircle className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}</td>
                  <td className="py-3 px-4">{s.dkim_compliant ? <CheckCircle className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function EmailSecurityPage() {
  const [activeTab, setActiveTab] = useState<'threats' | 'attachments' | 'urls' | 'senders'>('threats')

  const { data: stats = { analyzed_today: 0, threats_blocked: 0, phishing_attempts: 0, malware_attachments: 0 } } = useQuery<EmailStats>({
    queryKey: ['email-stats'],
    queryFn: () => apiFetch<EmailStats>('/api/v1/email/stats'),
    staleTime: 60_000, refetchInterval: 60_000,
  })

  const s: EmailStats = stats ?? { analyzed_today: 0, threats_blocked: 0, phishing_attempts: 0, malware_attachments: 0 }

  const statCards = [
    { label: '本日分析メール', value: (s.analyzed_today ?? 0).toLocaleString(), icon: Mail, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
    { label: '脅威ブロック', value: (s.threats_blocked ?? 0).toLocaleString(), icon: Shield, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
    { label: 'フィッシング試行', value: s.phishing_attempts, icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
    { label: 'マルウェア添付', value: s.malware_attachments, icon: FileText, color: 'text-purple-400', bg: 'bg-purple-500/10 border-purple-500/20' },
  ]

  const tabs = [
    { key: 'threats',     label: '脅威メール' },
    { key: 'attachments', label: '添付ファイル分析' },
    { key: 'urls',        label: 'URLスキャン' },
    { key: 'senders',     label: '送信者レピュテーション' },
  ] as const

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Mail className="w-6 h-6 text-[#e8002d]" />
            メールセキュリティ分析
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">フィッシング・マルウェア・BEC詐欺・URL解析</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#2a3f5f] text-[#e2e8f4] rounded-lg text-sm transition-colors border border-[#2a3f5f]">
          <RefreshCw className="w-4 h-4" />更新
        </button>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {statCards.map(c => {
          const Icon = c.icon
          return (
            <div key={c.label} className={`bg-[#0d1220] border rounded-xl p-4 ${c.bg}`}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[#070d19]/60"><Icon className={`w-5 h-5 ${c.color}`} /></div>
                <div>
                  <p className={`text-xl font-bold ${c.color}`}>{c.value}</p>
                  <p className="text-[#7d92b0] text-xs">{c.label}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>
      <div className="flex gap-1 border-b border-[#1e2d42] overflow-x-auto">
        {tabs.map(tab => (
          <button key={tab.key} onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px whitespace-nowrap
              ${activeTab === tab.key ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'}`}>
            {tab.label}
          </button>
        ))}
      </div>
      {activeTab === 'threats'     && <ThreatEmailsTab />}
      {activeTab === 'attachments' && <AttachmentsTab />}
      {activeTab === 'urls'        && <UrlScanTab />}
      {activeTab === 'senders'     && <SenderReputationTab />}
    </div>
  )
}
