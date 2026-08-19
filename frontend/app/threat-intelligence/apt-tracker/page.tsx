'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Radar, Search, Filter, Plus, X, ChevronRight, Globe, Shield,
  AlertTriangle, Calendar, Target, Clock, CheckCircle2, Activity,
  Layers, Database, Flag, Eye, RefreshCw, Map, Crosshair, Bug,
  Link2, ExternalLink, Info, TrendingUp, BarChart2, Network,
  FileText, Lock, Zap, ChevronDown, ChevronUp,
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type CampaignPhase =
  | 'initial_access'
  | 'execution'
  | 'persistence'
  | 'lateral_movement'
  | 'exfil'
  | 'completed'

type CampaignStatus = 'active' | 'concluded' | 'suspected'

interface TTP {
  technique_id: string
  technique_name: string
  tactic: string
  date: string
  description: string
}

interface C2Entry {
  value: string
  type: 'domain' | 'ip'
  provider: string
  asn: string
  country: string
}

interface MalwareUsed {
  name: string
  family: string
  role: 'dropper' | 'backdoor' | 'stealer' | 'loader' | 'ransomware'
}

interface IOC {
  type: 'hash' | 'ip' | 'domain'
  value: string
  description: string
}

interface VictimOrg {
  industry: string
  country: string
  count: number
}

interface APTCampaign {
  id: string
  campaign_name: string
  apt_group: string
  apt_group_id: string
  start_date: string
  end_date: string | null
  target_sectors: string[]
  target_countries: string[]
  techniques_used: TTP[]
  phase: CampaignPhase
  confidence: number
  status: CampaignStatus
  description: string
  attribution: string
  motivation: string
  infrastructure: C2Entry[]
  malware_used: MalwareUsed[]
  iocs: IOC[]
  victims: VictimOrg[]
  related_campaigns: string[]
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_CAMPAIGNS: APTCampaign[] = [
  {
    id: 'camp-001',
    campaign_name: 'Operation Midnight Snow',
    apt_group: 'APT29',
    apt_group_id: 'ta-apt29',
    start_date: '2025-09-01',
    end_date: null,
    target_sectors: ['Government', 'Defense', 'Think Tank'],
    target_countries: ['US', 'UK', 'DE'],
    techniques_used: [
      { technique_id: 'T1566.001', technique_name: 'Spearphishing Attachment', tactic: 'initial-access', date: '2025-09-01', description: 'Targeted spearphishing with malicious Word docs' },
      { technique_id: 'T1059.001', technique_name: 'PowerShell', tactic: 'execution', date: '2025-09-05', description: 'Encoded PowerShell commands for payload delivery' },
      { technique_id: 'T1547.001', technique_name: 'Registry Run Keys', tactic: 'persistence', date: '2025-09-08', description: 'Persistence via registry modifications' },
      { technique_id: 'T1021.001', technique_name: 'Remote Desktop Protocol', tactic: 'lateral-movement', date: '2025-09-15', description: 'Lateral movement via RDP' },
      { technique_id: 'T1041', technique_name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration', date: '2025-10-01', description: 'Data exfil over encrypted C2' },
    ],
    phase: 'lateral_movement',
    confidence: 88,
    status: 'active',
    description: 'Sophisticated espionage campaign targeting Western government institutions leveraging custom malware and living-off-the-land techniques.',
    attribution: 'Russian SVR (Foreign Intelligence Service)',
    motivation: 'Geopolitical intelligence gathering targeting NATO-aligned governments',
    infrastructure: [
      { value: 'update-service.org', type: 'domain', provider: 'Cloudflare', asn: 'AS13335', country: 'US' },
      { value: '185.220.101.45', type: 'ip', provider: 'M247 Ltd', asn: 'AS9009', country: 'RO' },
      { value: 'cdn-delivery.net', type: 'domain', provider: 'Namecheap', asn: 'AS22612', country: 'US' },
    ],
    malware_used: [
      { name: 'SUNBURST', family: 'Backdoor', role: 'backdoor' },
      { name: 'TEARDROP', family: 'Loader', role: 'loader' },
      { name: 'GoldFinder', family: 'HTTP Tracer', role: 'backdoor' },
    ],
    iocs: [
      { type: 'hash', value: 'd0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600', description: 'SUNBURST DLL hash' },
      { type: 'domain', value: 'avsvmcloud.com', description: 'C2 domain used by SUNBURST' },
      { type: 'ip', value: '13.59.205.95', description: 'C2 infrastructure IP' },
    ],
    victims: [
      { industry: 'Government', country: 'US', count: 4 },
      { industry: 'Defense Contractor', country: 'UK', count: 2 },
      { industry: 'Think Tank', country: 'DE', count: 1 },
    ],
    related_campaigns: ['camp-007'],
  },
  {
    id: 'camp-002',
    campaign_name: 'TraderTraitor Redux',
    apt_group: 'Lazarus',
    apt_group_id: 'ta-lazarus',
    start_date: '2025-10-15',
    end_date: null,
    target_sectors: ['Financial', 'Crypto Exchange', 'DeFi'],
    target_countries: ['JP', 'KR', 'US', 'SG'],
    techniques_used: [
      { technique_id: 'T1195.002', technique_name: 'Compromise Software Supply Chain', tactic: 'initial-access', date: '2025-10-15', description: 'Supply chain compromise via npm packages' },
      { technique_id: 'T1059.007', technique_name: 'JavaScript', tactic: 'execution', date: '2025-10-17', description: 'Malicious JS payload in compromised npm' },
      { technique_id: 'T1027', technique_name: 'Obfuscated Files', tactic: 'defense-evasion', date: '2025-10-20', description: 'Heavy obfuscation techniques' },
      { technique_id: 'T1071.001', technique_name: 'Web Protocols', tactic: 'command-and-control', date: '2025-10-22', description: 'HTTPS-based C2 communication' },
    ],
    phase: 'exfil',
    confidence: 92,
    status: 'active',
    description: 'Continuation of the TraderTraitor campaign series targeting cryptocurrency exchanges for financial gain through supply chain compromise.',
    attribution: 'North Korean Lazarus Group (HIDDEN COBRA)',
    motivation: 'Financial gain — cryptocurrency theft to fund DPRK weapons programs',
    infrastructure: [
      { value: 'npm-registry.dev', type: 'domain', provider: 'DigitalOcean', asn: 'AS14061', country: 'NL' },
      { value: '104.21.93.214', type: 'ip', provider: 'Cloudflare', asn: 'AS13335', country: 'US' },
    ],
    malware_used: [
      { name: 'BLINDINGCAN', family: 'RAT', role: 'backdoor' },
      { name: 'COPPERHEDGE', family: 'Tunneling Tool', role: 'loader' },
    ],
    iocs: [
      { type: 'hash', value: 'a93ee7ea13238bd038bcbec635f500e3e9b13598bf8a43ee85d1acfccd7735bf', description: 'BLINDINGCAN payload hash' },
      { type: 'domain', value: 'npm-registry.dev', description: 'Malicious npm registry mirror' },
    ],
    victims: [
      { industry: 'Crypto Exchange', country: 'JP', count: 2 },
      { industry: 'DeFi Protocol', country: 'US', count: 1 },
    ],
    related_campaigns: [],
  },
  {
    id: 'camp-003',
    campaign_name: 'Operation Double Dragon',
    apt_group: 'APT41',
    apt_group_id: 'ta-apt41',
    start_date: '2025-07-20',
    end_date: null,
    target_sectors: ['Healthcare', 'Telecom', 'Technology'],
    target_countries: ['IN', 'TW', 'US', 'AU'],
    techniques_used: [
      { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'initial-access', date: '2025-07-20', description: 'Exploited CVE-2024-3400 in Palo Alto GlobalProtect' },
      { technique_id: 'T1105', technique_name: 'Ingress Tool Transfer', tactic: 'command-and-control', date: '2025-07-25', description: 'Transfer of KEYPLUG backdoor' },
      { technique_id: 'T1505.003', technique_name: 'Web Shell', tactic: 'persistence', date: '2025-07-28', description: 'BEHINDER web shell deployment' },
      { technique_id: 'T1560', technique_name: 'Archive Collected Data', tactic: 'collection', date: '2025-08-10', description: 'Data staged for exfiltration' },
    ],
    phase: 'persistence',
    confidence: 76,
    status: 'active',
    description: 'Dual-purpose APT campaign with both espionage and financial crime objectives targeting high-value technology and healthcare sectors.',
    attribution: 'Chinese APT41 (BARIUM/Winnti)',
    motivation: 'Dual-purpose: state-sponsored espionage and financial crime',
    infrastructure: [
      { value: 'health-updates.info', type: 'domain', provider: 'GoDaddy', asn: 'AS26496', country: 'US' },
      { value: '45.76.100.88', type: 'ip', provider: 'Vultr', asn: 'AS20473', country: 'SG' },
    ],
    malware_used: [
      { name: 'KEYPLUG', family: 'Modular Backdoor', role: 'backdoor' },
      { name: 'BEHINDER', family: 'Web Shell', role: 'dropper' },
      { name: 'DUSTPAN', family: 'Dropper', role: 'dropper' },
    ],
    iocs: [
      { type: 'hash', value: '5d0ffbc8389f27b0649696f0ef5b3cfe95c067891740e12eacf17e3d4dcc5e8c', description: 'KEYPLUG sample hash' },
      { type: 'ip', value: '45.76.100.88', description: 'KEYPLUG C2 server' },
    ],
    victims: [
      { industry: 'Healthcare', country: 'US', count: 3 },
      { industry: 'Telecom', country: 'IN', count: 2 },
    ],
    related_campaigns: [],
  },
  {
    id: 'camp-004',
    campaign_name: 'Fancy Bear OPSEC',
    apt_group: 'APT28',
    apt_group_id: 'ta-apt28',
    start_date: '2025-05-10',
    end_date: '2025-11-30',
    target_sectors: ['Military', 'Government', 'Media'],
    target_countries: ['UA', 'PL', 'FR', 'DE'],
    techniques_used: [
      { technique_id: 'T1566.002', technique_name: 'Spearphishing Link', tactic: 'initial-access', date: '2025-05-10', description: 'Targeted phishing with credential harvesting pages' },
      { technique_id: 'T1078', technique_name: 'Valid Accounts', tactic: 'defense-evasion', date: '2025-05-20', description: 'Use of compromised credentials' },
      { technique_id: 'T1003.001', technique_name: 'LSASS Memory', tactic: 'credential-access', date: '2025-06-01', description: 'Credential dumping via LSASS' },
    ],
    phase: 'completed',
    confidence: 95,
    status: 'concluded',
    description: 'Military intelligence gathering campaign targeting Ukrainian military and allied European government entities.',
    attribution: 'Russian GRU Unit 26165 (Fancy Bear)',
    motivation: 'Military intelligence gathering related to Ukraine conflict',
    infrastructure: [
      { value: 'secure-mail.eu', type: 'domain', provider: 'OVH', asn: 'AS16276', country: 'FR' },
      { value: '91.108.4.21', type: 'ip', provider: 'Hetzner', asn: 'AS24940', country: 'DE' },
    ],
    malware_used: [
      { name: 'X-Agent', family: 'Implant', role: 'backdoor' },
      { name: 'Sofacy', family: 'Downloader', role: 'dropper' },
    ],
    iocs: [
      { type: 'domain', value: 'secure-mail.eu', description: 'Phishing domain' },
    ],
    victims: [
      { industry: 'Military', country: 'UA', count: 6 },
      { industry: 'Government', country: 'PL', count: 2 },
    ],
    related_campaigns: [],
  },
  {
    id: 'camp-005',
    campaign_name: 'Kimsuky Recon Series',
    apt_group: 'Kimsuky',
    apt_group_id: 'ta-kimsuky',
    start_date: '2025-11-01',
    end_date: null,
    target_sectors: ['Policy', 'NGO', 'Academic'],
    target_countries: ['KR', 'US', 'JP'],
    techniques_used: [
      { technique_id: 'T1598.003', technique_name: 'Spearphishing Link', tactic: 'reconnaissance', date: '2025-11-01', description: 'Credential phishing via fake login pages' },
      { technique_id: 'T1114.001', technique_name: 'Local Email Collection', tactic: 'collection', date: '2025-11-10', description: 'Email harvesting from compromised accounts' },
    ],
    phase: 'initial_access',
    confidence: 71,
    status: 'active',
    description: 'Ongoing reconnaissance and intelligence collection campaign targeting North Korea policy researchers and Korean government bodies.',
    attribution: 'North Korean Kimsuky (Velvet Chollima)',
    motivation: 'Intelligence gathering on North Korea policy and sanctions',
    infrastructure: [
      { value: 'korea-research.net', type: 'domain', provider: 'Namecheap', asn: 'AS22612', country: 'US' },
    ],
    malware_used: [
      { name: 'BabyShark', family: 'Recon Tool', role: 'dropper' },
    ],
    iocs: [
      { type: 'domain', value: 'korea-research.net', description: 'Credential phishing domain' },
    ],
    victims: [
      { industry: 'Policy Think Tank', country: 'US', count: 2 },
      { industry: 'Academic', country: 'KR', count: 3 },
    ],
    related_campaigns: [],
  },
  {
    id: 'camp-006',
    campaign_name: 'SilverFox Finance',
    apt_group: 'FIN7',
    apt_group_id: 'ta-fin7',
    start_date: '2025-08-01',
    end_date: '2025-12-31',
    target_sectors: ['Retail', 'Restaurant', 'Hospitality'],
    target_countries: ['US', 'CA', 'AU'],
    techniques_used: [
      { technique_id: 'T1204.002', technique_name: 'Malicious File', tactic: 'execution', date: '2025-08-01', description: 'Malicious Office documents with macros' },
      { technique_id: 'T1056.001', technique_name: 'Keylogging', tactic: 'collection', date: '2025-08-15', description: 'POS terminal keylogger deployment' },
      { technique_id: 'T1005', technique_name: 'Data from Local System', tactic: 'collection', date: '2025-09-01', description: 'POS card data harvesting' },
    ],
    phase: 'exfil',
    confidence: 84,
    status: 'concluded',
    description: 'POS malware campaign targeting retail and hospitality sector for payment card data theft.',
    attribution: 'FIN7 (Carbanak Group)',
    motivation: 'Financial — payment card fraud and sale of stolen card data',
    infrastructure: [
      { value: 'updates-cdn.com', type: 'domain', provider: 'AWS', asn: 'AS16509', country: 'US' },
    ],
    malware_used: [
      { name: 'CARBANAK', family: 'Backdoor', role: 'backdoor' },
      { name: 'PILLOWMINT', family: 'POS Scraper', role: 'stealer' },
    ],
    iocs: [
      { type: 'hash', value: 'e38e0a93f7e29a7efaac0add30e6d63f1046f75a47f8cbf47c7b8d0f86cc7a37', description: 'PILLOWMINT hash' },
    ],
    victims: [
      { industry: 'Retail', country: 'US', count: 8 },
      { industry: 'Restaurant Chain', country: 'CA', count: 3 },
    ],
    related_campaigns: [],
  },
  {
    id: 'camp-007',
    campaign_name: 'Cozy Bear Revisited',
    apt_group: 'APT29',
    apt_group_id: 'ta-apt29',
    start_date: '2025-06-15',
    end_date: '2025-09-30',
    target_sectors: ['Pharmaceutical', 'Healthcare', 'Research'],
    target_countries: ['US', 'UK', 'CA'],
    techniques_used: [
      { technique_id: 'T1133', technique_name: 'External Remote Services', tactic: 'initial-access', date: '2025-06-15', description: 'Exploitation of VPN appliances' },
      { technique_id: 'T1553.002', technique_name: 'Code Signing', tactic: 'defense-evasion', date: '2025-06-25', description: 'Signed malware using stolen certificates' },
    ],
    phase: 'completed',
    confidence: 90,
    status: 'concluded',
    description: 'Targeted COVID-19 vaccine research institutions and pharmaceutical companies for IP theft.',
    attribution: 'Russian SVR APT29 (Cozy Bear)',
    motivation: 'Intellectual property theft — COVID-19 vaccine research',
    infrastructure: [
      { value: '195.123.246.55', type: 'ip', provider: 'Frantech', asn: 'AS53667', country: 'US' },
    ],
    malware_used: [
      { name: 'WellMess', family: 'Implant', role: 'backdoor' },
      { name: 'WellMail', family: 'Implant', role: 'backdoor' },
    ],
    iocs: [
      { type: 'ip', value: '195.123.246.55', description: 'WellMess C2' },
    ],
    victims: [
      { industry: 'Pharmaceutical', country: 'UK', count: 2 },
      { industry: 'Research Lab', country: 'CA', count: 1 },
    ],
    related_campaigns: ['camp-001'],
  },
  {
    id: 'camp-008',
    campaign_name: 'SolarRise Infrastructure',
    apt_group: 'Volt Typhoon',
    apt_group_id: 'ta-vt',
    start_date: '2025-03-01',
    end_date: null,
    target_sectors: ['Critical Infrastructure', 'Energy', 'Water', 'Telecom'],
    target_countries: ['US', 'GU', 'AU'],
    techniques_used: [
      { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'initial-access', date: '2025-03-01', description: 'FortiGuard and Cisco exploits' },
      { technique_id: 'T1036', technique_name: 'Masquerading', tactic: 'defense-evasion', date: '2025-03-10', description: 'Living-off-the-land, blending with normal traffic' },
      { technique_id: 'T1133', technique_name: 'External Remote Services', tactic: 'persistence', date: '2025-04-01', description: 'VPN credential abuse for persistent access' },
      { technique_id: 'T1016', technique_name: 'System Network Configuration Discovery', tactic: 'discovery', date: '2025-04-15', description: 'OT/ICS network mapping' },
    ],
    phase: 'persistence',
    confidence: 82,
    status: 'active',
    description: 'Long-term pre-positioning campaign targeting US critical infrastructure, likely for disruptive capabilities in a potential conflict scenario.',
    attribution: 'Chinese Volt Typhoon (Bronze Silhouette)',
    motivation: 'Pre-positioning for potential destructive attacks on critical infrastructure',
    infrastructure: [
      { value: '50.114.10.72', type: 'ip', provider: 'ARIN', asn: 'AS7922', country: 'US' },
      { value: '192.168.100.1', type: 'ip', provider: 'SOHO Router', asn: 'N/A', country: 'US' },
    ],
    malware_used: [
      { name: 'KV-botnet', family: 'Botnet', role: 'loader' },
    ],
    iocs: [
      { type: 'ip', value: '50.114.10.72', description: 'Compromised SOHO router used as relay' },
    ],
    victims: [
      { industry: 'Water Utility', country: 'US', count: 2 },
      { industry: 'Power Grid', country: 'US', count: 1 },
    ],
    related_campaigns: [],
  },
]

// ─── Helper Functions ─────────────────────────────────────────────────────────

const COUNTRY_FLAGS: Record<string, string> = {
  US: '🇺🇸', UK: '🇬🇧', DE: '🇩🇪', FR: '🇫🇷', JP: '🇯🇵', KR: '🇰🇷',
  CN: '🇨🇳', RU: '🇷🇺', IN: '🇮🇳', AU: '🇦🇺', CA: '🇨🇦', SG: '🇸🇬',
  NL: '🇳🇱', UA: '🇺🇦', PL: '🇵🇱', TW: '🇹🇼', GU: '🇬🇺', RO: '🇷🇴',
}

function getPhaseLabel(phase: CampaignPhase): string {
  const map: Record<CampaignPhase, string> = {
    initial_access: '初期アクセス',
    execution: '実行',
    persistence: '永続化',
    lateral_movement: '横展開',
    exfil: '情報窃取',
    completed: '完了',
  }
  return map[phase]
}

function getPhaseBadgeClass(phase: CampaignPhase): string {
  const map: Record<CampaignPhase, string> = {
    initial_access: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/40',
    execution: 'bg-orange-900/40 text-orange-400 border-orange-700/40',
    persistence: 'bg-red-900/40 text-red-400 border-red-700/40',
    lateral_movement: 'bg-purple-900/40 text-purple-400 border-purple-700/40',
    exfil: 'bg-rose-900/40 text-rose-400 border-rose-700/40',
    completed: 'bg-slate-700/40 text-slate-400 border-slate-600/40',
  }
  return map[phase]
}

function getStatusBadgeClass(status: CampaignStatus): string {
  const map: Record<CampaignStatus, string> = {
    active: 'bg-green-900/40 text-green-400 border-green-700/40',
    concluded: 'bg-slate-700/40 text-slate-400 border-slate-600/40',
    suspected: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/40',
  }
  return map[status]
}

function getStatusLabel(status: CampaignStatus): string {
  return { active: 'アクティブ', concluded: '終了', suspected: '疑い' }[status]
}

function getRoleColor(role: string): string {
  const map: Record<string, string> = {
    dropper: 'bg-yellow-900/40 text-yellow-400',
    backdoor: 'bg-red-900/40 text-red-400',
    stealer: 'bg-orange-900/40 text-orange-400',
    loader: 'bg-purple-900/40 text-purple-400',
    ransomware: 'bg-rose-900/40 text-rose-400',
  }
  return map[role] ?? 'bg-slate-700 text-slate-300'
}

function getIOCTypeColor(type: string): string {
  const map: Record<string, string> = {
    hash: 'bg-blue-900/40 text-blue-400',
    ip: 'bg-orange-900/40 text-orange-400',
    domain: 'bg-purple-900/40 text-purple-400',
  }
  return map[type] ?? 'bg-slate-700 text-slate-300'
}

const MITRE_TACTICS = [
  'initial-access', 'execution', 'persistence', 'privilege-escalation',
  'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
  'collection', 'command-and-control', 'exfiltration', 'impact',
]

const TACTIC_LABELS: Record<string, string> = {
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Priv Esc',
  'defense-evasion': 'Def Evasion',
  'credential-access': 'Cred Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Move',
  'collection': 'Collection',
  'command-and-control': 'C2',
  'exfiltration': 'Exfil',
  'impact': 'Impact',
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function MITREMatrix({ techniques }: { techniques: TTP[] }) {
  const byTactic: Record<string, TTP[]> = {}
  techniques.forEach(t => {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = []
    byTactic[t.tactic].push(t)
  })

  return (
    <div className="overflow-x-auto">
      <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${MITRE_TACTICS.length}, minmax(90px, 1fr))` }}>
        {MITRE_TACTICS.map(tactic => (
          <div key={tactic} className="min-w-[90px]">
            <div className="text-[10px] font-bold text-[#7d92b0] bg-[#0d1220] border border-[#1e2d42] px-1.5 py-1 rounded-t text-center truncate">
              {TACTIC_LABELS[tactic] || tactic}
            </div>
            <div className="border border-t-0 border-[#1e2d42] rounded-b min-h-[60px] p-1 space-y-0.5">
              {(byTactic[tactic] || []).map(t => (
                <div
                  key={t.technique_id}
                  title={t.technique_name}
                  className="text-[9px] bg-[#e8002d]/20 border border-[#e8002d]/30 text-[#ff6b6b] rounded-sm px-1 py-0.5 truncate"
                >
                  {t.technique_id}
                </div>
              ))}
              {!byTactic[tactic] && (
                <div className="h-8" />
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function CampaignDetailModal({
  campaign,
  onClose,
  allCampaigns,
}: {
  campaign: APTCampaign
  onClose: () => void
  allCampaigns: APTCampaign[]
}) {
  const [activeTab, setActiveTab] = useState<
    'overview' | 'timeline' | 'infra' | 'malware' | 'iocs' | 'victims' | 'related' | 'mitre'
  >('overview')

  const relatedCampaigns = allCampaigns.filter(c =>
    campaign.related_campaigns.includes(c.id) || c.apt_group_id === campaign.apt_group_id && c.id !== campaign.id
  )

  const tabs = [
    { id: 'overview', label: '概要' },
    { id: 'timeline', label: 'タイムライン' },
    { id: 'infra', label: 'インフラ' },
    { id: 'malware', label: 'マルウェア' },
    { id: 'iocs', label: 'IOC' },
    { id: 'victims', label: '被害組織' },
    { id: 'related', label: '関連' },
    { id: 'mitre', label: 'MITRE' },
  ] as const

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/80 overflow-y-auto py-4">
      <div className="w-full max-w-5xl mx-4 bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-[#1e2d42]">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className={`text-xs px-2 py-0.5 rounded-sm border font-medium ${getStatusBadgeClass(campaign.status)}`}>
                {getStatusLabel(campaign.status)}
              </span>
              <span className={`text-xs px-2 py-0.5 rounded-sm border font-medium ${getPhaseBadgeClass(campaign.phase)}`}>
                {getPhaseLabel(campaign.phase)}
              </span>
            </div>
            <h2 className="text-xl font-bold text-white">{campaign.campaign_name}</h2>
            <p className="text-sm text-[#7d92b0] mt-0.5">
              <span className="text-[#e8002d] font-medium">{campaign.apt_group}</span>
              {' · '}
              {campaign.start_date} → {campaign.end_date ?? '継続中'}
              {' · '}信頼度 {campaign.confidence}%
            </p>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white p-1">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-0.5 px-5 pt-3 border-b border-[#1e2d42] overflow-x-auto">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-3 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-[#e8002d] text-white'
                  : 'border-transparent text-[#7d92b0] hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="p-5">
          {/* Overview */}
          {activeTab === 'overview' && (
            <div className="space-y-4">
              <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
                <h3 className="text-sm font-semibold text-white mb-2">キャンペーン概要</h3>
                <p className="text-sm text-[#7d92b0] leading-relaxed">{campaign.description}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-white mb-2">帰属分析</h3>
                  <p className="text-sm text-[#7d92b0]">{campaign.attribution}</p>
                  <div className="mt-2 flex items-center gap-2">
                    <span className="text-xs text-[#7d92b0]">信頼度</span>
                    <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-linear-to-r from-[#e8002d] to-[#ff6b6b]"
                        style={{ width: `${campaign.confidence}%` }}
                      />
                    </div>
                    <span className="text-xs text-white font-bold">{campaign.confidence}%</span>
                  </div>
                </div>
                <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-white mb-2">動機</h3>
                  <p className="text-sm text-[#7d92b0]">{campaign.motivation}</p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-white mb-2">標的セクター</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {campaign.target_sectors.map(s => (
                      <span key={s} className="text-xs px-2 py-0.5 bg-[#1e2d42] rounded-sm text-[#7d92b0]">{s}</span>
                    ))}
                  </div>
                </div>
                <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-white mb-2">標的国</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {campaign.target_countries.map(c => (
                      <span key={c} className="text-sm">{COUNTRY_FLAGS[c] ?? '🌐'} {c}</span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Timeline */}
          {activeTab === 'timeline' && (
            <div className="relative">
              <div className="absolute left-[100px] top-0 bottom-0 w-px bg-[#1e2d42]" />
              <div className="space-y-4">
                {campaign.techniques_used.map((ttp, i) => (
                  <div key={i} className="flex gap-4 relative">
                    <div className="w-[100px] text-right">
                      <span className="text-xs text-[#7d92b0]">{ttp.date}</span>
                    </div>
                    <div className="relative shrink-0 mt-1">
                      <div className="w-3 h-3 rounded-full bg-[#e8002d] border-2 border-[#070d19] relative z-10" />
                    </div>
                    <div className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 mb-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono font-bold text-[#e8002d]">{ttp.technique_id}</span>
                        <span className="text-sm font-medium text-white">{ttp.technique_name}</span>
                        <span className="text-xs text-[#7d92b0] bg-[#1e2d42] px-1.5 py-0.5 rounded-sm">{ttp.tactic}</span>
                      </div>
                      <p className="text-xs text-[#7d92b0]">{ttp.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Infrastructure */}
          {activeTab === 'infra' && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['種別', '値', 'プロバイダー', 'ASN', '国'].map(h => (
                      <th key={h} className="text-left py-2 px-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {campaign.infrastructure.map((entry, i) => (
                    <tr key={i} className="border-b border-[#1e2d42]/40 hover:bg-[#070d19]/60">
                      <td className="py-2 px-3">
                        <span className={`text-xs px-1.5 py-0.5 rounded-sm ${
                          entry.type === 'domain' ? 'bg-blue-900/40 text-blue-400' : 'bg-orange-900/40 text-orange-400'
                        }`}>
                          {entry.type.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-2 px-3 font-mono text-xs text-white">{entry.value}</td>
                      <td className="py-2 px-3 text-[#7d92b0]">{entry.provider}</td>
                      <td className="py-2 px-3 text-[#7d92b0] font-mono text-xs">{entry.asn}</td>
                      <td className="py-2 px-3 text-[#7d92b0]">{COUNTRY_FLAGS[entry.country] ?? '🌐'} {entry.country}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Malware */}
          {activeTab === 'malware' && (
            <div className="space-y-3">
              {campaign.malware_used.map((m, i) => (
                <div key={i} className="flex items-center gap-3 bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
                  <Bug className="w-5 h-5 text-[#e8002d] shrink-0" />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white">{m.name}</span>
                      <span className="text-xs text-[#7d92b0]">{m.family}</span>
                    </div>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded-sm font-medium ${getRoleColor(m.role)}`}>
                    {m.role}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* IOCs */}
          {activeTab === 'iocs' && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['種別', '値', '説明'].map(h => (
                      <th key={h} className="text-left py-2 px-3 text-xs text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {campaign.iocs.map((ioc, i) => (
                    <tr key={i} className="border-b border-[#1e2d42]/40 hover:bg-[#070d19]/60">
                      <td className="py-2 px-3">
                        <span className={`text-xs px-1.5 py-0.5 rounded-sm ${getIOCTypeColor(ioc.type)}`}>
                          {ioc.type.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-2 px-3 font-mono text-xs text-white max-w-[300px] truncate">{ioc.value}</td>
                      <td className="py-2 px-3 text-[#7d92b0]">{ioc.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Victims */}
          {activeTab === 'victims' && (
            <div className="space-y-3">
              <p className="text-xs text-[#7d92b0] italic">注：組織名は匿名化されています</p>
              {campaign.victims.map((v, i) => (
                <div key={i} className="flex items-center gap-3 bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
                  <div className="w-8 h-8 rounded-full bg-[#1e2d42] flex items-center justify-center shrink-0">
                    <span className="text-sm">{COUNTRY_FLAGS[v.country] ?? '🌐'}</span>
                  </div>
                  <div className="flex-1">
                    <span className="text-sm font-medium text-white">{v.industry}</span>
                    <p className="text-xs text-[#7d92b0]">{v.country}</p>
                  </div>
                  <span className="text-sm font-bold text-[#e8002d]">{v.count}組織</span>
                </div>
              ))}
            </div>
          )}

          {/* Related */}
          {activeTab === 'related' && (
            <div className="space-y-3">
              {relatedCampaigns.length === 0 ? (
                <p className="text-sm text-[#7d92b0] text-center py-8">関連キャンペーンなし</p>
              ) : (
                relatedCampaigns.map(rc => (
                  <div key={rc.id} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-white">{rc.campaign_name}</span>
                      <span className="text-xs text-[#e8002d]">{rc.apt_group}</span>
                    </div>
                    <p className="text-xs text-[#7d92b0]">{rc.start_date} → {rc.end_date ?? '継続中'}</p>
                  </div>
                ))
              )}
            </div>
          )}

          {/* MITRE */}
          {activeTab === 'mitre' && (
            <div>
              <h3 className="text-sm font-semibold text-white mb-3">MITRE ATT&CK カバレッジ</h3>
              <MITREMatrix techniques={campaign.techniques_used} />
              <div className="mt-4">
                <p className="text-xs text-[#7d92b0]">
                  合計 {campaign.techniques_used.length} テクニック / {new Set(campaign.techniques_used.map(t => t.tactic)).size} タクティクス
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function AddCampaignModal({ onClose, onAdd }: { onClose: () => void; onAdd: (c: APTCampaign) => void }) {
  const [form, setForm] = useState({
    campaign_name: '',
    apt_group: '',
    start_date: '',
    end_date: '',
    target_sectors: '',
    target_countries: '',
    description: '',
    attribution: '',
    motivation: '',
    phase: 'initial_access' as CampaignPhase,
    confidence: '70',
    status: 'active' as CampaignStatus,
  })

  const handleSubmit = () => {
    const newCampaign: APTCampaign = {
      id: `camp-${Date.now()}`,
      campaign_name: form.campaign_name,
      apt_group: form.apt_group,
      apt_group_id: `ta-${form.apt_group.toLowerCase().replace(/\s/g, '-')}`,
      start_date: form.start_date,
      end_date: form.end_date || null,
      target_sectors: form.target_sectors.split(',').map(s => s.trim()).filter(Boolean),
      target_countries: form.target_countries.split(',').map(s => s.trim()).filter(Boolean),
      techniques_used: [],
      phase: form.phase,
      confidence: parseInt(form.confidence),
      status: form.status,
      description: form.description,
      attribution: form.attribution,
      motivation: form.motivation,
      infrastructure: [],
      malware_used: [],
      iocs: [],
      victims: [],
      related_campaigns: [],
    }
    onAdd(newCampaign)
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
      <div className="w-full max-w-xl mx-4 bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl">
        <div className="flex items-center justify-between p-4 border-b border-[#1e2d42]">
          <h2 className="text-lg font-bold text-white">新規キャンペーン追加</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-4 space-y-3 max-h-[70vh] overflow-y-auto">
          {[
            { label: 'キャンペーン名', key: 'campaign_name', placeholder: 'Operation ...' },
            { label: 'APTグループ', key: 'apt_group', placeholder: 'APT29, Lazarus...' },
            { label: '開始日', key: 'start_date', placeholder: 'YYYY-MM-DD' },
            { label: '終了日', key: 'end_date', placeholder: 'YYYY-MM-DD (空白=継続中)' },
            { label: '標的セクター (カンマ区切り)', key: 'target_sectors', placeholder: 'Government, Finance' },
            { label: '標的国 (カンマ区切り)', key: 'target_countries', placeholder: 'US, JP, DE' },
            { label: '概要', key: 'description', placeholder: 'キャンペーンの説明' },
            { label: '帰属', key: 'attribution', placeholder: '帰属先の詳細' },
            { label: '動機', key: 'motivation', placeholder: '攻撃者の動機' },
            { label: '信頼度 (%)', key: 'confidence', placeholder: '70' },
          ].map(f => (
            <div key={f.key}>
              <label className="text-xs text-[#7d92b0] mb-1 block">{f.label}</label>
              <input
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/60"
                placeholder={f.placeholder}
                value={(form as Record<string, string>)[f.key]}
                onChange={e => setForm(prev => ({ ...prev, [f.key]: e.target.value }))}
              />
            </div>
          ))}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">フェーズ</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden"
                value={form.phase}
                onChange={e => setForm(prev => ({ ...prev, phase: e.target.value as CampaignPhase }))}
              >
                {(['initial_access', 'execution', 'persistence', 'lateral_movement', 'exfil', 'completed'] as CampaignPhase[]).map(p => (
                  <option key={p} value={p}>{getPhaseLabel(p)}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-[#7d92b0] mb-1 block">ステータス</label>
              <select
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden"
                value={form.status}
                onChange={e => setForm(prev => ({ ...prev, status: e.target.value as CampaignStatus }))}
              >
                <option value="active">アクティブ</option>
                <option value="concluded">終了</option>
                <option value="suspected">疑い</option>
              </select>
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] rounded-sm">
            キャンセル
          </button>
          <button
            onClick={handleSubmit}
            disabled={!form.campaign_name || !form.apt_group}
            className="px-4 py-2 text-sm text-white bg-[#e8002d] hover:bg-[#c0001f] rounded-sm disabled:opacity-50"
          >
            追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Timeline View ────────────────────────────────────────────────────────────

function TimelineView({ campaigns }: { campaigns: APTCampaign[] }) {
  const [zoom, setZoom] = useState<'6m' | '1y' | '2y' | 'all'>('1y')

  const now = new Date('2026-03-18')
  const zoomMs: Record<string, number> = {
    '6m': 6 * 30 * 24 * 60 * 60 * 1000,
    '1y': 365 * 24 * 60 * 60 * 1000,
    '2y': 2 * 365 * 24 * 60 * 60 * 1000,
    'all': 5 * 365 * 24 * 60 * 60 * 1000,
  }

  const windowMs = zoomMs[zoom]
  const startWindow = new Date(now.getTime() - windowMs)

  const visibleCampaigns = campaigns.filter(c => {
    const end = c.end_date ? new Date(c.end_date) : now
    const start = new Date(c.start_date)
    return end >= startWindow && start <= now
  })

  // Simple overlap detection — assign rows
  const rows: APTCampaign[][] = []
  const sorted = [...visibleCampaigns].sort((a, b) => a.start_date.localeCompare(b.start_date))

  for (const campaign of sorted) {
    const cStart = new Date(campaign.start_date).getTime()
    const cEnd = campaign.end_date ? new Date(campaign.end_date).getTime() : now.getTime()

    let placed = false
    for (const row of rows) {
      const lastInRow = row[row.length - 1]
      const lastEnd = lastInRow.end_date ? new Date(lastInRow.end_date).getTime() : now.getTime()
      if (cStart > lastEnd) {
        row.push(campaign)
        placed = true
        break
      }
    }
    if (!placed) rows.push([campaign])
  }

  const getLeftPct = (dateStr: string) => {
    const d = Math.max(new Date(dateStr).getTime(), startWindow.getTime())
    return ((d - startWindow.getTime()) / windowMs) * 100
  }

  const getWidthPct = (campaign: APTCampaign) => {
    const start = Math.max(new Date(campaign.start_date).getTime(), startWindow.getTime())
    const end = Math.min(
      campaign.end_date ? new Date(campaign.end_date).getTime() : now.getTime(),
      now.getTime()
    )
    return Math.max(((end - start) / windowMs) * 100, 0.5)
  }

  const APT_COLORS: Record<string, string> = {
    'APT29': '#e8002d',
    'APT28': '#ff6b35',
    'APT41': '#f59e0b',
    'Lazarus': '#8b5cf6',
    'Kimsuky': '#06b6d4',
    'FIN7': '#10b981',
    'Volt Typhoon': '#3b82f6',
  }

  const getColor = (group: string) => APT_COLORS[group] ?? '#7d92b0'

  return (
    <div className="space-y-4">
      {/* Zoom controls */}
      <div className="flex items-center gap-2">
        <span className="text-sm text-[#7d92b0]">期間:</span>
        {(['6m', '1y', '2y', 'all'] as const).map(z => (
          <button
            key={z}
            onClick={() => setZoom(z)}
            className={`px-3 py-1.5 text-xs rounded-sm border transition-colors ${
              zoom === z
                ? 'bg-[#e8002d]/20 border-[#e8002d]/50 text-[#e8002d]'
                : 'border-[#1e2d42] text-[#7d92b0] hover:text-white'
            }`}
          >
            {{ '6m': '直近6ヶ月', '1y': '1年', '2y': '2年', 'all': '全期間' }[z]}
          </button>
        ))}
      </div>

      {/* Timeline */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
        {/* Date ruler */}
        <div className="relative h-6 mb-2 ml-[140px]">
          {[0, 25, 50, 75, 100].map(pct => {
            const d = new Date(startWindow.getTime() + (pct / 100) * windowMs)
            return (
              <div key={pct} className="absolute text-[10px] text-[#3d5068]" style={{ left: `${pct}%` }}>
                {d.toLocaleDateString('ja-JP', { month: 'short', year: '2-digit' })}
              </div>
            )
          })}
        </div>

        {/* Rows */}
        {rows.map((row, rowIdx) => (
          <div key={rowIdx} className="relative h-10 mb-1">
            {row.map(campaign => {
              const left = getLeftPct(campaign.start_date)
              const width = getWidthPct(campaign)
              const color = getColor(campaign.apt_group)

              return (
                <div
                  key={campaign.id}
                  className="absolute top-1 flex items-center h-8 rounded-sm px-2 text-xs font-medium text-white cursor-pointer overflow-hidden"
                  style={{
                    left: `calc(140px + ${left}%)`,
                    width: `calc(${width}% - 2px)`,
                    minWidth: '20px',
                    backgroundColor: color + '33',
                    borderLeft: `3px solid ${color}`,
                  }}
                  title={`${campaign.campaign_name} (${campaign.apt_group})`}
                >
                  <span className="truncate">{campaign.campaign_name}</span>
                </div>
              )
            })}
          </div>
        ))}

        {visibleCampaigns.length === 0 && (
          <p className="text-sm text-[#7d92b0] text-center py-8">この期間にキャンペーンなし</p>
        )}

        {/* Legend */}
        <div className="mt-4 flex flex-wrap gap-2 border-t border-[#1e2d42] pt-3">
          {Object.entries(APT_COLORS).map(([group, color]) => (
            <div key={group} className="flex items-center gap-1">
              <div className="w-3 h-3 rounded-xs" style={{ backgroundColor: color }} />
              <span className="text-xs text-[#7d92b0]">{group}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function APTTrackerPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'campaigns' | 'timeline'>('campaigns')
  const [search, setSearch] = useState('')
  const [filterGroup, setFilterGroup] = useState('')
  const [filterSector, setFilterSector] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [selectedCampaign, setSelectedCampaign] = useState<APTCampaign | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  const [extraCampaigns, setExtraCampaigns] = useState<APTCampaign[]>([])

  const { data: apiCampaigns, isLoading } = useQuery<APTCampaign[]>({
    queryKey: ['apt-campaigns'],
    queryFn: () => apiFetch('/api/v1/threat-intel/apt-campaigns'),
    staleTime: 60_000,
    retry: false,
  })

  const allCampaigns = useMemo(() => {
    const base = apiCampaigns ?? m(MOCK_CAMPAIGNS)
    return [...base, ...extraCampaigns]
  }, [apiCampaigns, extraCampaigns])

  const filteredCampaigns = useMemo(() => {
    return allCampaigns.filter(c => {
      if (search && !c.campaign_name.toLowerCase().includes(search.toLowerCase()) && !c.apt_group.toLowerCase().includes(search.toLowerCase())) return false
      if (filterGroup && c.apt_group !== filterGroup) return false
      if (filterSector && !c.target_sectors.includes(filterSector)) return false
      if (filterStatus && c.status !== filterStatus) return false
      return true
    })
  }, [allCampaigns, search, filterGroup, filterSector, filterStatus])

  const activeLast30 = useMemo(() => {
    const cutoff = new Date('2026-03-18')
    cutoff.setDate(cutoff.getDate() - 30)
    return allCampaigns.filter(c => {
      if (c.status !== 'active') return false
      return new Date(c.start_date) <= new Date('2026-03-18')
    }).length
  }, [allCampaigns])

  const allGroups = [...new Set(allCampaigns.map(c => c.apt_group))].sort()
  const allSectors = [...new Set(allCampaigns.flatMap(c => c.target_sectors))].sort()

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
            <Radar className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">APTキャンペーントラッカー</h1>
            <p className="text-sm text-[#7d92b0]">高度持続型脅威のキャンペーン追跡・分析</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ['apt-campaigns'] })}
            className="p-2 border border-[#1e2d42] rounded-sm text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] text-white text-sm rounded-sm hover:bg-[#c0001f] transition-colors"
          >
            <Plus className="w-4 h-4" />
            キャンペーン追加
          </button>
        </div>
      </div>

      {/* Active campaigns banner */}
      <div className="bg-[#e8002d]/10 border border-[#e8002d]/20 rounded-lg px-4 py-3 flex items-center gap-3">
        <div className="w-2 h-2 rounded-full bg-[#e8002d] animate-pulse shrink-0" />
        <p className="text-sm text-white">
          過去30日間に <span className="font-bold text-[#e8002d]">{activeLast30}</span> 件のアクティブキャンペーンを観測。
          全{allCampaigns.length}件のキャンペーンをトラッキング中。
        </p>
        <div className="ml-auto flex gap-4 text-sm">
          {(['active', 'concluded', 'suspected'] as CampaignStatus[]).map(s => (
            <span key={s} className="text-[#7d92b0]">
              {getStatusLabel(s)}: <span className="text-white font-medium">{allCampaigns.filter(c => c.status === s).length}</span>
            </span>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-0.5 border-b border-[#1e2d42]">
        {[
          { id: 'campaigns', label: 'キャンペーン' },
          { id: 'timeline', label: 'タイムライン' },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as 'campaigns' | 'timeline')}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              activeTab === tab.id
                ? 'border-[#e8002d] text-white'
                : 'border-transparent text-[#7d92b0] hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Campaigns Tab */}
      {activeTab === 'campaigns' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
              <input
                className="w-full pl-9 pr-3 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-sm text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#e8002d]/50"
                placeholder="キャンペーン名・APTグループで検索..."
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            <select
              className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#7d92b0] focus:outline-hidden"
              value={filterGroup}
              onChange={e => setFilterGroup(e.target.value)}
            >
              <option value="">全APTグループ</option>
              {allGroups.map(g => <option key={g} value={g}>{g}</option>)}
            </select>
            <select
              className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#7d92b0] focus:outline-hidden"
              value={filterSector}
              onChange={e => setFilterSector(e.target.value)}
            >
              <option value="">全セクター</option>
              {allSectors.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select
              className="bg-[#0d1220] border border-[#1e2d42] rounded-sm px-3 py-2 text-sm text-[#7d92b0] focus:outline-hidden"
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value)}
            >
              <option value="">全ステータス</option>
              <option value="active">アクティブ</option>
              <option value="concluded">終了</option>
              <option value="suspected">疑い</option>
            </select>
          </div>

          {/* Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42] bg-[#070d19]/60">
                    {['キャンペーン', 'APTグループ', '期間', '標的セクター', '標的国', 'TTP数', 'フェーズ', '信頼度', 'ステータス', ''].map(h => (
                      <th key={h} className="text-left py-3 px-3 text-xs text-[#7d92b0] font-medium whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {isLoading ? (
                    <tr><td colSpan={10} className="text-center py-8 text-[#7d92b0]">読み込み中...</td></tr>
                  ) : filteredCampaigns.length === 0 ? (
                    <tr><td colSpan={10} className="text-center py-8 text-[#7d92b0]">キャンペーンが見つかりません</td></tr>
                  ) : filteredCampaigns.map(campaign => (
                    <tr
                      key={campaign.id}
                      className="border-b border-[#1e2d42]/40 hover:bg-[#070d19]/60 cursor-pointer group"
                      onClick={() => setSelectedCampaign(campaign)}
                    >
                      <td className="py-3 px-3">
                        <span className="font-medium text-white group-hover:text-[#e8002d] transition-colors">{campaign.campaign_name}</span>
                      </td>
                      <td className="py-3 px-3">
                        <span className="text-[#e8002d] font-medium">{campaign.apt_group}</span>
                      </td>
                      <td className="py-3 px-3 text-[#7d92b0] text-xs whitespace-nowrap">
                        {campaign.start_date}<br />{campaign.end_date ?? <span className="text-green-400">継続中</span>}
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex flex-wrap gap-1">
                          {campaign.target_sectors.slice(0, 2).map(s => (
                            <span key={s} className="text-xs px-1.5 py-0.5 bg-[#1e2d42] rounded-sm text-[#7d92b0]">{s}</span>
                          ))}
                          {campaign.target_sectors.length > 2 && (
                            <span className="text-xs text-[#3d5068]">+{campaign.target_sectors.length - 2}</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex gap-0.5">
                          {campaign.target_countries.slice(0, 4).map(c => (
                            <span key={c} className="text-sm" title={c}>{COUNTRY_FLAGS[c] ?? '🌐'}</span>
                          ))}
                          {campaign.target_countries.length > 4 && (
                            <span className="text-xs text-[#3d5068] ml-0.5">+{campaign.target_countries.length - 4}</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 bg-[#1e2d42] rounded-sm font-medium text-white">
                          <Target className="w-3 h-3 text-[#e8002d]" />
                          {campaign.techniques_used.length}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border font-medium ${getPhaseBadgeClass(campaign.phase)}`}>
                          {getPhaseLabel(campaign.phase)}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-1.5">
                          <div className="w-12 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                            <div
                              className="h-full rounded-full bg-linear-to-r from-[#e8002d] to-[#ff6b6b]"
                              style={{ width: `${campaign.confidence}%` }}
                            />
                          </div>
                          <span className="text-xs text-white">{campaign.confidence}%</span>
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <span className={`text-xs px-2 py-0.5 rounded-sm border font-medium ${getStatusBadgeClass(campaign.status)}`}>
                          {getStatusLabel(campaign.status)}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <ChevronRight className="w-4 h-4 text-[#3d5068] group-hover:text-[#7d92b0]" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Timeline Tab */}
      {activeTab === 'timeline' && <TimelineView campaigns={allCampaigns} />}

      {/* Campaign Detail Modal */}
      {selectedCampaign && (
        <CampaignDetailModal
          campaign={selectedCampaign}
          onClose={() => setSelectedCampaign(null)}
          allCampaigns={allCampaigns}
        />
      )}

      {/* Add Campaign Modal */}
      {showAddModal && (
        <AddCampaignModal
          onClose={() => setShowAddModal(false)}
          onAdd={c => setExtraCampaigns(prev => [...prev, c])}
        />
      )}
    </div>
  )
}
