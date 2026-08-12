'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Users, Search, Filter, Plus, X, ChevronRight, Globe, Shield,
  AlertTriangle, Calendar, Target, Bug, Link2, ExternalLink,
  Clock, CheckCircle2, XCircle, Activity, Layers, Database,
  Flag, Crosshair, Eye, RefreshCw,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type Motivation = 'espionage' | 'financial' | 'hacktivism' | 'disruption'
type Sophistication = 'nation-state' | 'advanced' | 'intermediate' | 'basic'
type Sponsorship = 'state' | 'criminal' | 'independent'
type ActorStatus = 'active' | 'inactive'
type RelationType = 'same_group' | 'allied' | 'inspired'

interface MalwareFamily {
  name: string
  type: string
  first_seen: string
  sophistication: string
}

interface Campaign {
  name: string
  date: string
  targeted_sectors: string[]
  status: 'ongoing' | 'concluded' | 'suspected'
}

interface RelatedActor {
  id: string
  name: string
  relationship: RelationType
}

interface TTPsByTactic {
  [tactic: string]: string[]
}

interface C2Infrastructure {
  domains: string[]
  ips: string[]
  hosting_providers: string[]
  geolocations: string[]
}

interface ThreatActor {
  id: string
  name: string
  aliases: string[]
  origin_country: string
  origin_flag: string
  motivation: Motivation[]
  sophistication: Sophistication
  sponsorship: Sponsorship
  first_seen: number
  last_active: string
  status: ActorStatus
  target_sectors: string[]
  malware_families: MalwareFamily[]
  description: string
  attribution_confidence: number
  ttps: TTPsByTactic
  infrastructure: C2Infrastructure
  campaigns: Campaign[]
  related_actors: RelatedActor[]
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_ACTORS: ThreatActor[] = [
  {
    id: 'ta-001',
    name: 'APT-PHANTOM',
    aliases: ['ShadowDragon', 'Nightfall', 'UNC4521'],
    origin_country: '中国',
    origin_flag: '🇨🇳',
    motivation: ['espionage'],
    sophistication: 'nation-state',
    sponsorship: 'state',
    first_seen: 2015,
    last_active: '2026-03-10',
    status: 'active',
    target_sectors: ['防衛', '航空宇宙', '政府', 'テクノロジー'],
    malware_families: [
      { name: 'PhantomRAT', type: 'RAT', first_seen: '2016-03', sophistication: '高' },
      { name: 'ShadowLoader', type: 'Loader', first_seen: '2018-07', sophistication: '高' },
      { name: 'NightBeacon', type: 'Backdoor', first_seen: '2020-01', sophistication: '非常に高' },
    ],
    description: 'APT-PHANTOMは中国人民解放軍と関連が疑われる高度持続的脅威グループです。主に防衛・航空宇宙分野を標的とし、長期的な諜報活動と知的財産の窃取を行います。スピアフィッシングと水飲み場攻撃を主なベクターとして使用し、カスタムマルウェアによる長期潜伏が特徴です。',
    attribution_confidence: 87,
    ttps: {
      'Initial Access': ['T1566.001 - Spearphishing Attachment', 'T1190 - Exploit Public-Facing Application', 'T1195 - Supply Chain Compromise'],
      'Execution': ['T1059.003 - Windows Command Shell', 'T1059.001 - PowerShell', 'T1106 - Native API'],
      'Persistence': ['T1547.001 - Registry Run Keys', 'T1053.005 - Scheduled Task', 'T1505.003 - Web Shell'],
      'Defense Evasion': ['T1036 - Masquerading', 'T1055 - Process Injection', 'T1140 - Deobfuscate/Decode Files'],
      'Collection': ['T1560 - Archive Collected Data', 'T1213 - Data from Information Repositories'],
      'Exfiltration': ['T1041 - Exfiltration Over C2 Channel', 'T1048 - Exfiltration Over Alternative Protocol'],
    },
    infrastructure: {
      domains: ['update-service[.]com', 'cdn-delivery[.]net', 'api-gateway[.]org'],
      ips: ['45.32.18.124', '192.168.proxy', '103.224.182.61'],
      hosting_providers: ['Choopa LLC', 'Vultr Holdings', 'Linode'],
      geolocations: ['香港', 'シンガポール', '米国（偽装）'],
    },
    campaigns: [
      { name: 'Operation SilentEagle', date: '2024-09', targeted_sectors: ['防衛', '航空宇宙'], status: 'concluded' },
      { name: 'Operation NightVision', date: '2025-03', targeted_sectors: ['政府', 'テクノロジー'], status: 'concluded' },
      { name: 'Operation PhantomWatch', date: '2026-01', targeted_sectors: ['防衛', '研究機関'], status: 'ongoing' },
    ],
    related_actors: [
      { id: 'ta-003', name: 'DRAGONCLAW', relationship: 'allied' },
      { id: 'ta-005', name: 'IRONVEIL', relationship: 'same_group' },
    ],
  },
  {
    id: 'ta-002',
    name: 'LAZARUS-X',
    aliases: ['Guardians of Peace', 'WHOis Team', 'Hidden Cobra'],
    origin_country: '北朝鮮',
    origin_flag: '🇰🇵',
    motivation: ['financial', 'espionage'],
    sophistication: 'nation-state',
    sponsorship: 'state',
    first_seen: 2009,
    last_active: '2026-03-15',
    status: 'active',
    target_sectors: ['金融', '暗号資産', 'メディア', '政府'],
    malware_families: [
      { name: 'BLINDINGCAN', type: 'RAT', first_seen: '2020-08', sophistication: '高' },
      { name: 'TAINTEDSCRIBE', type: 'Tunneling', first_seen: '2021-05', sophistication: '高' },
      { name: 'CryptoStealer', type: 'Stealer', first_seen: '2022-01', sophistication: '中' },
    ],
    description: 'LAZARUS-Xは北朝鮮政府系ハッカーグループで、制裁回避のための外貨獲得を主目的としています。暗号資産取引所への攻撃で知られ、数十億ドル規模の盗難を実行したとされています。サプライチェーン攻撃やゼロデイ脆弱性の利用にも長けています。',
    attribution_confidence: 92,
    ttps: {
      'Initial Access': ['T1566.002 - Spearphishing Link', 'T1195.002 - Compromise Software Supply Chain'],
      'Execution': ['T1204.002 - Malicious File', 'T1059.001 - PowerShell'],
      'Persistence': ['T1543.003 - Windows Service', 'T1547.001 - Registry Run Keys'],
      'Impact': ['T1486 - Data Encrypted for Impact', 'T1657 - Financial Theft'],
      'Collection': ['T1056.001 - Keylogging', 'T1539 - Steal Web Session Cookie'],
    },
    infrastructure: {
      domains: ['blockchain-verify[.]io', 'crypto-exchange-api[.]com', 'defi-protocol[.]net'],
      ips: ['175.45.176.0', '210.52.109.22', '91.245.253.72'],
      hosting_providers: ['OVH', 'Contabo', 'Hetzner Online'],
      geolocations: ['ロシア', 'オランダ', '中国'],
    },
    campaigns: [
      { name: 'Operation AppleJeus', date: '2024-06', targeted_sectors: ['暗号資産'], status: 'concluded' },
      { name: 'Operation DreamJob', date: '2025-01', targeted_sectors: ['金融', 'テクノロジー'], status: 'ongoing' },
    ],
    related_actors: [
      { id: 'ta-007', name: 'TEMP.Hermit', relationship: 'same_group' },
    ],
  },
  {
    id: 'ta-003',
    name: 'DRAGONCLAW',
    aliases: ['APT41', 'Winnti', 'Barium'],
    origin_country: '中国',
    origin_flag: '🇨🇳',
    motivation: ['espionage', 'financial'],
    sophistication: 'nation-state',
    sponsorship: 'state',
    first_seen: 2012,
    last_active: '2026-02-28',
    status: 'active',
    target_sectors: ['ヘルスケア', 'テクノロジー', 'ゲーム', '通信'],
    malware_families: [
      { name: 'Winnti', type: 'Backdoor', first_seen: '2013-01', sophistication: '非常に高' },
      { name: 'DEADEYE', type: 'Dropper', first_seen: '2021-03', sophistication: '高' },
      { name: 'LOWKEY', type: 'Backdoor', first_seen: '2022-07', sophistication: '高' },
    ],
    description: 'DRAGONCLAWは中国政府系の金銭目的と諜報目的の両方を持つ稀有なグループです。ゲーム会社への攻撃で不正な仮想通貨を生成しながら、政府機関や医療機関への諜報活動も並行して行います。ゼロデイ脆弱性の活用と高度なサプライチェーン汚染が特徴です。',
    attribution_confidence: 85,
    ttps: {
      'Initial Access': ['T1190 - Exploit Public-Facing Application', 'T1195.002 - Compromise Software Supply Chain'],
      'Execution': ['T1059.003 - Windows Command Shell', 'T1047 - Windows Management Instrumentation'],
      'Persistence': ['T1543.003 - Windows Service', 'T1505.003 - Web Shell'],
      'Collection': ['T1213 - Data from Information Repositories', 'T1005 - Data from Local System'],
    },
    infrastructure: {
      domains: ['github-update[.]com', 'microsoft-cdn[.]net', 'adobe-service[.]org'],
      ips: ['103.59.14.185', '45.142.212.100', '172.105.229.76'],
      hosting_providers: ['Alibaba Cloud', 'Tencent Cloud', 'Digital Ocean'],
      geolocations: ['中国', '香港', 'シンガポール'],
    },
    campaigns: [
      { name: 'Operation ShadowHammer', date: '2024-04', targeted_sectors: ['ゲーム', 'テクノロジー'], status: 'concluded' },
      { name: 'Operation ColunmTK', date: '2025-07', targeted_sectors: ['ヘルスケア'], status: 'concluded' },
    ],
    related_actors: [
      { id: 'ta-001', name: 'APT-PHANTOM', relationship: 'allied' },
    ],
  },
  {
    id: 'ta-004',
    name: 'COZY-BEAR',
    aliases: ['APT29', 'The Dukes', 'Midnight Blizzard'],
    origin_country: 'ロシア',
    origin_flag: '🇷🇺',
    motivation: ['espionage'],
    sophistication: 'nation-state',
    sponsorship: 'state',
    first_seen: 2008,
    last_active: '2026-03-12',
    status: 'active',
    target_sectors: ['政府', '外交', 'シンクタンク', 'テクノロジー'],
    malware_families: [
      { name: 'CosmicDuke', type: 'Backdoor', first_seen: '2014-02', sophistication: '非常に高' },
      { name: 'MiniDuke', type: 'Backdoor', first_seen: '2013-06', sophistication: '高' },
      { name: 'SUNBURST', type: 'Backdoor', first_seen: '2020-12', sophistication: '非常に高' },
    ],
    description: 'COZY-BEARはロシア連邦保安庁（FSB）またはロシア対外情報庁（SVR）に関連すると広く帰属されるグループです。SolarWindsサプライチェーン攻撃の実行者として最も著名であり、極めて高い技術力と忍耐力を持ち、数年単位での潜伏が確認されています。',
    attribution_confidence: 95,
    ttps: {
      'Initial Access': ['T1195.002 - Compromise Software Supply Chain', 'T1566.001 - Spearphishing Attachment'],
      'Execution': ['T1059.001 - PowerShell', 'T1218 - System Binary Proxy Execution'],
      'Defense Evasion': ['T1027 - Obfuscated Files or Information', 'T1036.005 - Match Legitimate Name or Location'],
      'Persistence': ['T1078 - Valid Accounts', 'T1553.002 - Code Signing'],
      'Exfiltration': ['T1567.002 - Exfiltration to Cloud Storage'],
    },
    infrastructure: {
      domains: ['solarwinds-cdn[.]com', 'azure-secure-api[.]net', 'o365-auth[.]org'],
      ips: ['51.89.143.234', '144.217.252.128', '77.81.98.121'],
      hosting_providers: ['OVH', 'Choopa', 'Frantech Solutions'],
      geolocations: ['ロシア', 'ウクライナ', 'チェコ'],
    },
    campaigns: [
      { name: 'SolarWinds Supply Chain Attack', date: '2020-12', targeted_sectors: ['政府', 'テクノロジー'], status: 'concluded' },
      { name: 'Microsoft Exchange Breach', date: '2024-01', targeted_sectors: ['テクノロジー', '政府'], status: 'concluded' },
      { name: 'Operation Midnight', date: '2025-11', targeted_sectors: ['外交', 'シンクタンク'], status: 'ongoing' },
    ],
    related_actors: [],
  },
  {
    id: 'ta-005',
    name: 'IRONVEIL',
    aliases: ['Sandworm', 'Voodoo Bear', 'BlackEnergy'],
    origin_country: 'ロシア',
    origin_flag: '🇷🇺',
    motivation: ['disruption', 'espionage'],
    sophistication: 'nation-state',
    sponsorship: 'state',
    first_seen: 2009,
    last_active: '2026-03-01',
    status: 'active',
    target_sectors: ['エネルギー', '重要インフラ', '軍事', 'メディア'],
    malware_families: [
      { name: 'Industroyer', type: 'ICS Malware', first_seen: '2016-12', sophistication: '非常に高' },
      { name: 'NotPetya', type: 'Wiper', first_seen: '2017-06', sophistication: '非常に高' },
      { name: 'Cyclops Blink', type: 'Botnet', first_seen: '2022-02', sophistication: '高' },
    ],
    description: 'IRONVEILはロシア軍参謀本部情報総局（GRU）に関連する最も破壊的な脅威グループの一つです。ウクライナ電力網攻撃やNotPetyaランサムウェアの展開者として知られ、国家規模のサイバー戦争能力を保有しています。ICS/SCADAシステムへの攻撃を専門とします。',
    attribution_confidence: 91,
    ttps: {
      'Initial Access': ['T1133 - External Remote Services', 'T1190 - Exploit Public-Facing Application'],
      'Execution': ['T1059.005 - Visual Basic', 'T1203 - Exploitation for Client Execution'],
      'Impact': ['T1485 - Data Destruction', 'T1499 - Endpoint Denial of Service', 'T1489 - Service Stop'],
      'Lateral Movement': ['T1021.002 - SMB/Windows Admin Shares', 'T1078 - Valid Accounts'],
    },
    infrastructure: {
      domains: ['ics-monitor[.]net', 'scada-update[.]com', 'energy-grid[.]org'],
      ips: ['94.185.85.122', '176.31.112.10', '85.187.236.119'],
      hosting_providers: ['OVH', 'Serverius', 'Quasi Networks'],
      geolocations: ['ロシア', 'フランス', 'オランダ'],
    },
    campaigns: [
      { name: 'Ukraine Power Grid Attack', date: '2022-04', targeted_sectors: ['エネルギー'], status: 'concluded' },
      { name: 'Operation Armageddon', date: '2024-08', targeted_sectors: ['軍事', '政府'], status: 'concluded' },
    ],
    related_actors: [
      { id: 'ta-001', name: 'APT-PHANTOM', relationship: 'inspired' },
    ],
  },
  {
    id: 'ta-006',
    name: 'CARBANAK',
    aliases: ['FIN7', 'Anunak', 'Navigator Group'],
    origin_country: 'ウクライナ/ロシア',
    origin_flag: '🇺🇦',
    motivation: ['financial'],
    sophistication: 'advanced',
    sponsorship: 'criminal',
    first_seen: 2013,
    last_active: '2025-12-20',
    status: 'active',
    target_sectors: ['金融', '小売', 'ホスピタリティ', 'レストラン'],
    malware_families: [
      { name: 'Carbanak', type: 'Banking Trojan', first_seen: '2014-01', sophistication: '高' },
      { name: 'GRIFFON', type: 'Backdoor', first_seen: '2017-05', sophistication: '中' },
      { name: 'BOOSTWRITE', type: 'Dropper', first_seen: '2019-09', sophistication: '中' },
    ],
    description: 'CARBANAKは金融機関とPOSシステムを標的とする世界最大規模のサイバー犯罪グループの一つです。10億ドル以上の銀行強盗を実行したとされ、その手口は精巧なスピアフィッシングから始まり、内部ネットワークを長期潜伏しながら金融システムを掌握します。',
    attribution_confidence: 78,
    ttps: {
      'Initial Access': ['T1566.001 - Spearphishing Attachment', 'T1566.002 - Spearphishing Link'],
      'Execution': ['T1059.007 - JavaScript', 'T1204.002 - Malicious File'],
      'Collection': ['T1125 - Video Capture', 'T1056.001 - Keylogging', 'T1113 - Screen Capture'],
      'Impact': ['T1657 - Financial Theft'],
    },
    infrastructure: {
      domains: ['payment-gateway[.]ru', 'bank-api[.]com', 'swift-transfer[.]net'],
      ips: ['46.161.27.191', '176.67.177.159', '193.189.100.195'],
      hosting_providers: ['Frantech Solutions', 'Abhosting', 'Leaseweb'],
      geolocations: ['ロシア', 'ウクライナ', 'モルドバ'],
    },
    campaigns: [
      { name: 'Global Bank Heist 2024', date: '2024-02', targeted_sectors: ['金融'], status: 'concluded' },
      { name: 'Restaurant Chain Breach', date: '2025-04', targeted_sectors: ['ホスピタリティ', 'レストラン'], status: 'concluded' },
    ],
    related_actors: [],
  },
  {
    id: 'ta-007',
    name: 'KILLNET',
    aliases: ['KillMilk', 'Black Skills', 'Infinity Forum'],
    origin_country: 'ロシア',
    origin_flag: '🇷🇺',
    motivation: ['hacktivism', 'disruption'],
    sophistication: 'intermediate',
    sponsorship: 'independent',
    first_seen: 2022,
    last_active: '2026-03-05',
    status: 'active',
    target_sectors: ['政府', '医療', '金融', 'メディア'],
    malware_families: [
      { name: 'KillNet DDoS Tool', type: 'DDoS Tool', first_seen: '2022-03', sophistication: '低' },
      { name: 'Passion Botnet', type: 'Botnet', first_seen: '2023-01', sophistication: '中' },
    ],
    description: 'KILLNETはロシア支持の親ロシアハクティビストグループで、NATO加盟国や西側政府機関へのDDoS攻撃で知られています。公開されたTelegramチャンネルを通じて攻撃を調整し、比較的低い技術レベルながら組織的な攻撃で混乱を引き起こします。',
    attribution_confidence: 65,
    ttps: {
      'Impact': ['T1498 - Network Denial of Service', 'T1499 - Endpoint Denial of Service'],
      'Initial Access': ['T1190 - Exploit Public-Facing Application'],
      'Resource Development': ['T1583.005 - Botnet'],
    },
    infrastructure: {
      domains: ['killnet-forum[.]ru', 'infinity-forum[.]net'],
      ips: ['91.108.4.0/22', '149.154.160.0/20'],
      hosting_providers: ['Telegram Infrastructure', 'Unknown'],
      geolocations: ['ロシア'],
    },
    campaigns: [
      { name: 'NATO Infrastructure Attack', date: '2024-03', targeted_sectors: ['政府', '軍事'], status: 'concluded' },
      { name: 'Hospital DDoS Wave', date: '2025-02', targeted_sectors: ['医療'], status: 'concluded' },
      { name: 'European Financial DDoS', date: '2026-01', targeted_sectors: ['金融'], status: 'ongoing' },
    ],
    related_actors: [],
  },
  {
    id: 'ta-008',
    name: 'SCATTERED-SPIDER',
    aliases: ['0ktapus', 'Star Fraud', 'Muddled Libra'],
    origin_country: '英語圏',
    origin_flag: '🌐',
    motivation: ['financial'],
    sophistication: 'advanced',
    sponsorship: 'criminal',
    first_seen: 2022,
    last_active: '2026-02-14',
    status: 'active',
    target_sectors: ['テクノロジー', '通信', 'カジノ', 'BPO'],
    malware_families: [
      { name: 'AveMaria RAT', type: 'RAT', first_seen: '2022-08', sophistication: '中' },
      { name: 'Spectre RAT', type: 'RAT', first_seen: '2023-04', sophistication: '中' },
    ],
    description: 'SCATTERED-SPIDERは英語圏のネイティブスピーカーで構成された若いサイバー犯罪グループで、ソーシャルエンジニアリングとSIMスワップ攻撃に卓越しています。MGMリゾーツやCaesarsエンターテイメントへの攻撃で知られ、Okta等のIDプロバイダーを標的とします。',
    attribution_confidence: 72,
    ttps: {
      'Initial Access': ['T1566.001 - Spearphishing Attachment', 'T1621 - Multi-Factor Authentication Request Generation'],
      'Persistence': ['T1078 - Valid Accounts', 'T1556 - Modify Authentication Process'],
      'Collection': ['T1539 - Steal Web Session Cookie', 'T1552 - Unsecured Credentials'],
      'Impact': ['T1486 - Data Encrypted for Impact', 'T1657 - Financial Theft'],
    },
    infrastructure: {
      domains: ['okta-verify[.]net', 'help-desk-support[.]com', 'mfa-bypass[.]io'],
      ips: ['185.220.101.0/24', '198.199.0.0/16'],
      hosting_providers: ['Digital Ocean', 'Linode', 'Cloudflare'],
      geolocations: ['米国', '英国', 'カナダ'],
    },
    campaigns: [
      { name: 'Casino Ransomware Wave', date: '2023-09', targeted_sectors: ['カジノ', 'ホスピタリティ'], status: 'concluded' },
      { name: 'Telecom SIM Swap Campaign', date: '2024-11', targeted_sectors: ['通信'], status: 'concluded' },
      { name: 'BPO Social Engineering', date: '2025-08', targeted_sectors: ['BPO', 'テクノロジー'], status: 'ongoing' },
    ],
    related_actors: [],
  },
]

// ─── Helpers ─────────────────────────────────────────────────────────────────

const MOTIVATION_COLORS: Record<Motivation, string> = {
  espionage: 'bg-blue-900/40 text-blue-300 border border-blue-700/40',
  financial: 'bg-green-900/40 text-green-300 border border-green-700/40',
  hacktivism: 'bg-purple-900/40 text-purple-300 border border-purple-700/40',
  disruption: 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
}

const MOTIVATION_LABELS: Record<Motivation, string> = {
  espionage: '諜報',
  financial: '金銭目的',
  hacktivism: 'ハクティビズム',
  disruption: '破壊活動',
}

const SOPHISTICATION_COLORS: Record<Sophistication, string> = {
  'nation-state': 'bg-[#e8002d]/20 text-[#e8002d] border border-[#e8002d]/30',
  'advanced': 'bg-orange-900/40 text-orange-300 border border-orange-700/40',
  'intermediate': 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40',
  'basic': 'bg-gray-900/40 text-gray-400 border border-gray-700/40',
}

const SOPHISTICATION_LABELS: Record<Sophistication, string> = {
  'nation-state': '国家レベル',
  'advanced': '高度',
  'intermediate': '中級',
  'basic': '基本',
}

const RELATION_LABELS: Record<RelationType, string> = {
  same_group: '同グループ',
  allied: '同盟',
  inspired: '影響を受けた',
}

const CAMPAIGN_STATUS_STYLES: Record<string, string> = {
  ongoing: 'bg-[#e8002d]/20 text-[#e8002d]',
  concluded: 'bg-gray-800 text-gray-400',
  suspected: 'bg-yellow-900/40 text-yellow-300',
}

// ─── Actor Card ───────────────────────────────────────────────────────────────

function ActorCard({ actor, onClick }: { actor: ThreatActor; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4
                 hover:border-[#e8002d]/40 hover:bg-[#111827] transition-all duration-150 group"
    >
      {/* Header row */}
      <div className="flex items-start justify-between mb-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-lg">{actor.origin_flag}</span>
            <h3 className="text-white font-bold text-sm group-hover:text-[#e8002d] transition-colors">
              {actor.name}
            </h3>
            <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
              actor.status === 'active'
                ? 'bg-green-900/40 text-green-400 border border-green-700/40'
                : 'bg-gray-800 text-gray-500 border border-gray-700/40'
            }`}>
              {actor.status === 'active' ? '活動中' : '非活動'}
            </span>
          </div>
          <p className="text-[#7d92b0] text-xs mt-1">{actor.origin_country}</p>
        </div>
        <ChevronRight className="w-4 h-4 text-[#3d5068] group-hover:text-[#e8002d] transition-colors mt-1" />
      </div>

      {/* Aliases */}
      {actor.aliases.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {actor.aliases.slice(0, 3).map(alias => (
            <span key={alias} className="text-[10px] px-2 py-0.5 rounded bg-[#161f33] text-[#7d92b0] border border-[#1e2d42]">
              {alias}
            </span>
          ))}
          {actor.aliases.length > 3 && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-[#161f33] text-[#7d92b0]">
              +{actor.aliases.length - 3}
            </span>
          )}
        </div>
      )}

      {/* Motivation & Sophistication */}
      <div className="flex flex-wrap gap-1.5 mb-3">
        {actor.motivation.map(m => (
          <span key={m} className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${MOTIVATION_COLORS[m]}`}>
            {MOTIVATION_LABELS[m]}
          </span>
        ))}
        <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${SOPHISTICATION_COLORS[actor.sophistication]}`}>
          {SOPHISTICATION_LABELS[actor.sophistication]}
        </span>
      </div>

      {/* Stats row */}
      <div className="flex items-center gap-4 text-xs text-[#7d92b0] mb-3">
        <span className="flex items-center gap-1">
          <Calendar className="w-3 h-3" />
          {actor.first_seen}年〜
        </span>
        <span className="flex items-center gap-1">
          <Clock className="w-3 h-3" />
          最終活動: {actor.last_active.slice(0, 7)}
        </span>
      </div>

      {/* Target sectors */}
      <div className="flex flex-wrap gap-1 mb-2">
        {actor.target_sectors.slice(0, 3).map(s => (
          <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0]">
            {s}
          </span>
        ))}
        {actor.target_sectors.length > 3 && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0]">
            +{actor.target_sectors.length - 3}
          </span>
        )}
      </div>

      {/* Malware families */}
      <div className="flex flex-wrap gap-1">
        {actor.malware_families.slice(0, 2).map(m => (
          <span key={m.name} className="text-[10px] px-1.5 py-0.5 rounded bg-[#e8002d]/10 text-[#e8002d]/80 border border-[#e8002d]/20">
            <Bug className="w-2.5 h-2.5 inline mr-0.5" />
            {m.name}
          </span>
        ))}
        {actor.malware_families.length > 2 && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#e8002d]/10 text-[#e8002d]/80">
            +{actor.malware_families.length - 2}
          </span>
        )}
      </div>
    </button>
  )
}

// ─── Actor Detail Modal ───────────────────────────────────────────────────────

function ActorDetailModal({ actor, onClose }: { actor: ThreatActor; onClose: () => void }) {
  const [activeTab, setActiveTab] = useState<'overview' | 'ttps' | 'infra' | 'malware' | 'campaigns' | 'related'>('overview')

  const tabs = [
    { id: 'overview', label: '概要' },
    { id: 'ttps', label: 'TTP/ATT&CK' },
    { id: 'infra', label: 'インフラ' },
    { id: 'malware', label: 'マルウェア' },
    { id: 'campaigns', label: 'キャンペーン' },
    { id: 'related', label: '関連アクター' },
  ] as const

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-start justify-center overflow-y-auto py-8 px-4">
      <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl w-full max-w-4xl">
        {/* Modal header */}
        <div className="flex items-start justify-between p-6 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <span className="text-3xl">{actor.origin_flag}</span>
            <div>
              <div className="flex items-center gap-3">
                <h2 className="text-white font-bold text-xl">{actor.name}</h2>
                <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${
                  actor.status === 'active'
                    ? 'bg-green-900/40 text-green-400 border border-green-700/40'
                    : 'bg-gray-800 text-gray-500'
                }`}>
                  {actor.status === 'active' ? '活動中' : '非活動'}
                </span>
                <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${SOPHISTICATION_COLORS[actor.sophistication]}`}>
                  {SOPHISTICATION_LABELS[actor.sophistication]}
                </span>
              </div>
              <p className="text-[#7d92b0] text-sm mt-1">{actor.origin_country} · {actor.sponsorship === 'state' ? '国家支援' : actor.sponsorship === 'criminal' ? '犯罪組織' : '独立'}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white p-1">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 px-6 pt-4 border-b border-[#1e2d42]">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 text-sm rounded-t font-medium transition-colors ${
                activeTab === tab.id
                  ? 'text-white border-b-2 border-[#e8002d]'
                  : 'text-[#7d92b0] hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div className="p-6">

          {/* Overview tab */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-white font-semibold mb-2">説明</h3>
                <p className="text-[#7d92b0] text-sm leading-relaxed">{actor.description}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#0d1220] rounded-lg p-4 border border-[#1e2d42]">
                  <p className="text-[#7d92b0] text-xs mb-1">帰属信頼度</p>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 h-2 bg-[#1e2d42] rounded-full">
                      <div
                        className="h-full rounded-full bg-[#e8002d]"
                        style={{ width: `${actor.attribution_confidence}%` }}
                      />
                    </div>
                    <span className="text-white font-bold text-sm">{actor.attribution_confidence}%</span>
                  </div>
                </div>
                <div className="bg-[#0d1220] rounded-lg p-4 border border-[#1e2d42]">
                  <p className="text-[#7d92b0] text-xs mb-1">スポンサーシップ</p>
                  <p className="text-white font-semibold">
                    {actor.sponsorship === 'state' ? '国家支援' : actor.sponsorship === 'criminal' ? '犯罪組織' : '独立系'}
                  </p>
                </div>
              </div>
              <div>
                <h3 className="text-white font-semibold mb-2">既知のエイリアス</h3>
                <div className="flex flex-wrap gap-2">
                  {actor.aliases.map(alias => (
                    <span key={alias} className="text-sm px-3 py-1 rounded bg-[#161f33] text-[#7d92b0] border border-[#1e2d42]">
                      {alias}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <h3 className="text-white font-semibold mb-2">動機</h3>
                <div className="flex flex-wrap gap-2">
                  {actor.motivation.map(m => (
                    <span key={m} className={`text-sm px-3 py-1 rounded-full font-medium ${MOTIVATION_COLORS[m]}`}>
                      {MOTIVATION_LABELS[m]}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <h3 className="text-white font-semibold mb-2">標的セクター</h3>
                <div className="flex flex-wrap gap-2">
                  {actor.target_sectors.map(s => (
                    <span key={s} className="text-sm px-3 py-1 rounded bg-[#1e2d42] text-[#7d92b0]">
                      {s}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TTPs tab */}
          {activeTab === 'ttps' && (
            <div className="space-y-4">
              <p className="text-[#7d92b0] text-sm">MITRE ATT&CKフレームワークに基づくTTP（戦術・技術・手順）</p>
              {Object.entries(actor.ttps).map(([tactic, techniques]) => (
                <div key={tactic} className="bg-[#0d1220] rounded-lg p-4 border border-[#1e2d42]">
                  <h4 className="text-white font-semibold text-sm mb-3 flex items-center gap-2">
                    <Target className="w-4 h-4 text-[#e8002d]" />
                    {tactic}
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {techniques.map(technique => (
                      <span key={technique} className="text-xs px-2.5 py-1 rounded bg-[#161f33] text-[#7d92b0] border border-[#1e2d42] font-mono">
                        {technique}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Infrastructure tab */}
          {activeTab === 'infra' && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#0d1220] rounded-lg p-4 border border-[#1e2d42]">
                  <h4 className="text-white font-semibold text-sm mb-3 flex items-center gap-2">
                    <Globe className="w-4 h-4 text-[#e8002d]" />
                    C2ドメイン
                  </h4>
                  <ul className="space-y-1.5">
                    {actor.infrastructure.domains.map(d => (
                      <li key={d} className="text-xs text-[#7d92b0] font-mono bg-[#161f33] px-2 py-1.5 rounded">{d}</li>
                    ))}
                  </ul>
                </div>
                <div className="bg-[#0d1220] rounded-lg p-4 border border-[#1e2d42]">
                  <h4 className="text-white font-semibold text-sm mb-3 flex items-center gap-2">
                    <Database className="w-4 h-4 text-[#e8002d]" />
                    既知のIPアドレス
                  </h4>
                  <ul className="space-y-1.5">
                    {actor.infrastructure.ips.map(ip => (
                      <li key={ip} className="text-xs text-[#7d92b0] font-mono bg-[#161f33] px-2 py-1.5 rounded">{ip}</li>
                    ))}
                  </ul>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#0d1220] rounded-lg p-4 border border-[#1e2d42]">
                  <h4 className="text-white font-semibold text-sm mb-3">ホスティングプロバイダー</h4>
                  <ul className="space-y-1.5">
                    {actor.infrastructure.hosting_providers.map(h => (
                      <li key={h} className="text-xs text-[#7d92b0]">{h}</li>
                    ))}
                  </ul>
                </div>
                <div className="bg-[#0d1220] rounded-lg p-4 border border-[#1e2d42]">
                  <h4 className="text-white font-semibold text-sm mb-3 flex items-center gap-2">
                    <Flag className="w-4 h-4 text-[#e8002d]" />
                    ジオロケーション
                  </h4>
                  <ul className="space-y-1.5">
                    {actor.infrastructure.geolocations.map(g => (
                      <li key={g} className="text-xs text-[#7d92b0]">{g}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Malware tab */}
          {activeTab === 'malware' && (
            <div>
              <p className="text-[#7d92b0] text-sm mb-4">このアクターと関連するマルウェアファミリー</p>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      <th className="text-left text-[#7d92b0] text-xs pb-3 font-medium">名前</th>
                      <th className="text-left text-[#7d92b0] text-xs pb-3 font-medium">タイプ</th>
                      <th className="text-left text-[#7d92b0] text-xs pb-3 font-medium">初観測</th>
                      <th className="text-left text-[#7d92b0] text-xs pb-3 font-medium">精巧度</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]">
                    {actor.malware_families.map(m => (
                      <tr key={m.name}>
                        <td className="py-3 text-white font-medium">
                          <div className="flex items-center gap-2">
                            <Bug className="w-3.5 h-3.5 text-[#e8002d]" />
                            {m.name}
                          </div>
                        </td>
                        <td className="py-3 text-[#7d92b0]">{m.type}</td>
                        <td className="py-3 text-[#7d92b0]">{m.first_seen}</td>
                        <td className="py-3 text-[#7d92b0]">{m.sophistication}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Campaigns tab */}
          {activeTab === 'campaigns' && (
            <div>
              <p className="text-[#7d92b0] text-sm mb-4">確認されているキャンペーン履歴</p>
              <div className="space-y-3">
                {actor.campaigns.map((c, i) => (
                  <div key={i} className="flex gap-4 bg-[#0d1220] rounded-lg p-4 border border-[#1e2d42]">
                    <div className="flex flex-col items-center">
                      <div className="w-3 h-3 rounded-full bg-[#e8002d] mt-1" />
                      {i < actor.campaigns.length - 1 && (
                        <div className="w-0.5 flex-1 bg-[#1e2d42] mt-1" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="text-white font-semibold text-sm">{c.name}</h4>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${CAMPAIGN_STATUS_STYLES[c.status]}`}>
                          {c.status === 'ongoing' ? '進行中' : c.status === 'concluded' ? '終了' : '疑い'}
                        </span>
                      </div>
                      <p className="text-[#7d92b0] text-xs mb-2">{c.date}</p>
                      <div className="flex flex-wrap gap-1">
                        {c.targeted_sectors.map(s => (
                          <span key={s} className="text-xs px-2 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0]">{s}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Related actors tab */}
          {activeTab === 'related' && (
            <div>
              {actor.related_actors.length === 0 ? (
                <p className="text-[#7d92b0] text-sm text-center py-8">関連アクターは登録されていません</p>
              ) : (
                <div className="space-y-3">
                  {actor.related_actors.map(r => (
                    <div key={r.id} className="flex items-center justify-between bg-[#0d1220] rounded-lg p-4 border border-[#1e2d42]">
                      <div className="flex items-center gap-3">
                        <Link2 className="w-4 h-4 text-[#e8002d]" />
                        <span className="text-white font-medium">{r.name}</span>
                      </div>
                      <span className="text-xs px-2.5 py-1 rounded-full bg-[#1e2d42] text-[#7d92b0]">
                        {RELATION_LABELS[r.relationship]}
                      </span>
                    </div>
                  ))}
                </div>
              )}
              {/* IOC cross-reference */}
              <div className="mt-6 pt-6 border-t border-[#1e2d42]">
                <a
                  href="/ioc"
                  className="flex items-center gap-2 px-4 py-2.5 rounded bg-[#e8002d]/10 border border-[#e8002d]/30
                             text-[#e8002d] text-sm font-medium hover:bg-[#e8002d]/20 transition-colors w-fit"
                >
                  <ExternalLink className="w-4 h-4" />
                  IOCを検索
                </a>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Add Actor Modal ──────────────────────────────────────────────────────────

function AddActorModal({ onClose, onSubmit }: { onClose: () => void; onSubmit: (data: Partial<ThreatActor>) => void }) {
  const [form, setForm] = useState({
    name: '',
    origin_country: '',
    origin_flag: '🌐',
    motivation: [] as Motivation[],
    sophistication: 'intermediate' as Sophistication,
    sponsorship: 'independent' as Sponsorship,
    first_seen: new Date().getFullYear(),
    description: '',
    target_sectors: '',
  })

  const MOTIVATIONS: Motivation[] = ['espionage', 'financial', 'hacktivism', 'disruption']

  const toggleMotivation = (m: Motivation) => {
    setForm(prev => ({
      ...prev,
      motivation: prev.motivation.includes(m)
        ? prev.motivation.filter(x => x !== m)
        : [...prev.motivation, m],
    }))
  }

  const handleSubmit = () => {
    if (!form.name.trim()) return
    onSubmit({
      ...form,
      target_sectors: form.target_sectors.split(',').map(s => s.trim()).filter(Boolean),
      aliases: [],
      malware_families: [],
      campaigns: [],
      related_actors: [],
      ttps: {},
      infrastructure: { domains: [], ips: [], hosting_providers: [], geolocations: [] },
      last_active: new Date().toISOString().slice(0, 10),
      status: 'active',
      attribution_confidence: 50,
    })
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg">
        <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
          <h3 className="text-white font-bold">新規アクター追加</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          <div>
            <label className="text-[#7d92b0] text-xs mb-1 block">アクター名 *</label>
            <input
              value={form.name}
              onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              placeholder="例: APT-UNKNOWN"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[#7d92b0] text-xs mb-1 block">出身国</label>
              <input
                value={form.origin_country}
                onChange={e => setForm(p => ({ ...p, origin_country: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
                placeholder="例: 中国"
              />
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs mb-1 block">国旗絵文字</label>
              <input
                value={form.origin_flag}
                onChange={e => setForm(p => ({ ...p, origin_flag: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              />
            </div>
          </div>
          <div>
            <label className="text-[#7d92b0] text-xs mb-2 block">動機</label>
            <div className="flex flex-wrap gap-2">
              {MOTIVATIONS.map(m => (
                <button
                  key={m}
                  onClick={() => toggleMotivation(m)}
                  className={`text-xs px-3 py-1.5 rounded-full font-medium transition-colors ${
                    form.motivation.includes(m)
                      ? MOTIVATION_COLORS[m]
                      : 'bg-[#161f33] text-[#7d92b0] border border-[#1e2d42]'
                  }`}
                >
                  {MOTIVATION_LABELS[m]}
                </button>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[#7d92b0] text-xs mb-1 block">精巧度</label>
              <select
                value={form.sophistication}
                onChange={e => setForm(p => ({ ...p, sophistication: e.target.value as Sophistication }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              >
                <option value="nation-state">国家レベル</option>
                <option value="advanced">高度</option>
                <option value="intermediate">中級</option>
                <option value="basic">基本</option>
              </select>
            </div>
            <div>
              <label className="text-[#7d92b0] text-xs mb-1 block">スポンサーシップ</label>
              <select
                value={form.sponsorship}
                onChange={e => setForm(p => ({ ...p, sponsorship: e.target.value as Sponsorship }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              >
                <option value="state">国家支援</option>
                <option value="criminal">犯罪組織</option>
                <option value="independent">独立系</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-[#7d92b0] text-xs mb-1 block">初観測年</label>
            <input
              type="number"
              value={form.first_seen}
              onChange={e => setForm(p => ({ ...p, first_seen: parseInt(e.target.value) }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
            />
          </div>
          <div>
            <label className="text-[#7d92b0] text-xs mb-1 block">標的セクター (カンマ区切り)</label>
            <input
              value={form.target_sectors}
              onChange={e => setForm(p => ({ ...p, target_sectors: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50"
              placeholder="例: 金融, 政府, テクノロジー"
            />
          </div>
          <div>
            <label className="text-[#7d92b0] text-xs mb-1 block">説明</label>
            <textarea
              value={form.description}
              onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
              rows={3}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50 resize-none"
              placeholder="アクターの概要..."
            />
          </div>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white transition-colors">
            キャンセル
          </button>
          <button
            onClick={handleSubmit}
            disabled={!form.name.trim()}
            className="px-4 py-2 text-sm bg-[#e8002d] text-white rounded font-medium
                       hover:bg-[#c5001f] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ThreatActorsPage() {
  const queryClient = useQueryClient()
  const [searchTerm, setSearchTerm] = useState('')
  const [filterOrigin, setFilterOrigin] = useState('')
  const [filterMotivation, setFilterMotivation] = useState<Motivation | ''>('')
  const [filterSector, setFilterSector] = useState('')
  const [filterSophistication, setFilterSophistication] = useState<Sophistication | ''>('')
  const [selectedActor, setSelectedActor] = useState<ThreatActor | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)

  const { data: actorsData, isLoading } = useQuery<ThreatActor[]>({
    queryKey: ['threat-actors'],
    queryFn: () => apiFetch('/api/v1/threat-intel/actors'),
    staleTime: 60_000,
  })

  const actors = actorsData ?? m(MOCK_ACTORS)

  const addMutation = useMutation({
    mutationFn: (data: Partial<ThreatActor>) => apiFetch('/api/v1/threat-intel/actors', { method: 'POST', body: JSON.stringify(data) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['threat-actors'] }),
  })

  // All unique origins, sectors for filter dropdowns
  const allOrigins = [...new Set(actors.map(a => a.origin_country))]
  const allSectors = [...new Set(actors.flatMap(a => a.target_sectors))]

  const filtered = actors.filter(a => {
    if (searchTerm && !a.name.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !a.aliases.some(al => al.toLowerCase().includes(searchTerm.toLowerCase()))) return false
    if (filterOrigin && a.origin_country !== filterOrigin) return false
    if (filterMotivation && !a.motivation.includes(filterMotivation as Motivation)) return false
    if (filterSector && !a.target_sectors.includes(filterSector)) return false
    if (filterSophistication && a.sophistication !== filterSophistication) return false
    return true
  })

  const activeCount = actors.filter(a => a.status === 'active').length
  const nationStateCount = actors.filter(a => a.sophistication === 'nation-state').length

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <Users className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-white font-bold text-xl">脅威アクタープロファイル</h1>
            <p className="text-[#7d92b0] text-sm">脅威アクターの追跡・プロファイリング</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ['threat-actors'] })}
            className="p-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm font-medium hover:bg-[#c5001f] transition-colors"
          >
            <Plus className="w-4 h-4" />
            新規アクター追加
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '総アクター数', value: actors.length, icon: Users, color: 'text-white' },
          { label: '活動中', value: activeCount, icon: Activity, color: 'text-[#e8002d]' },
          { label: '国家レベル', value: nationStateCount, icon: Shield, color: 'text-orange-400' },
          { label: '追跡対象セクター', value: allSectors.length, icon: Target, color: 'text-blue-400' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <div className="flex items-center gap-3">
              <Icon className={`w-5 h-5 ${color}`} />
              <div>
                <p className={`text-xl font-bold ${color}`}>{value}</p>
                <p className="text-[#7d92b0] text-xs">{label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 mb-6">
        <div className="flex flex-wrap gap-3 items-center">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0]" />
            <input
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              placeholder="アクター名またはエイリアスで検索..."
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 pl-9 text-white text-sm
                         focus:outline-none focus:border-[#e8002d]/50 placeholder:text-[#3d5068]"
            />
          </div>
          <select
            value={filterOrigin}
            onChange={e => setFilterOrigin(e.target.value)}
            className="bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#7d92b0] focus:outline-none focus:border-[#e8002d]/50 min-w-[140px]"
          >
            <option value="">全地域</option>
            {allOrigins.map(o => <option key={o} value={o}>{o}</option>)}
          </select>
          <select
            value={filterMotivation}
            onChange={e => setFilterMotivation(e.target.value as Motivation | '')}
            className="bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#7d92b0] focus:outline-none focus:border-[#e8002d]/50 min-w-[140px]"
          >
            <option value="">全動機</option>
            <option value="espionage">諜報</option>
            <option value="financial">金銭目的</option>
            <option value="hacktivism">ハクティビズム</option>
            <option value="disruption">破壊活動</option>
          </select>
          <select
            value={filterSector}
            onChange={e => setFilterSector(e.target.value)}
            className="bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#7d92b0] focus:outline-none focus:border-[#e8002d]/50 min-w-[140px]"
          >
            <option value="">全セクター</option>
            {allSectors.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select
            value={filterSophistication}
            onChange={e => setFilterSophistication(e.target.value as Sophistication | '')}
            className="bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#7d92b0] focus:outline-none focus:border-[#e8002d]/50 min-w-[140px]"
          >
            <option value="">全精巧度</option>
            <option value="nation-state">国家レベル</option>
            <option value="advanced">高度</option>
            <option value="intermediate">中級</option>
            <option value="basic">基本</option>
          </select>
          {(searchTerm || filterOrigin || filterMotivation || filterSector || filterSophistication) && (
            <button
              onClick={() => { setSearchTerm(''); setFilterOrigin(''); setFilterMotivation(''); setFilterSector(''); setFilterSophistication('') }}
              className="flex items-center gap-1 text-sm text-[#e8002d] hover:text-[#ff3355] transition-colors"
            >
              <X className="w-4 h-4" />
              クリア
            </button>
          )}
        </div>
        <p className="text-[#7d92b0] text-xs mt-2">{filtered.length} / {actors.length} アクターを表示</p>
      </div>

      {/* Actors grid */}
      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <div className="w-8 h-8 border-2 border-[#e8002d] border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-4">
          {filtered.map(actor => (
            <ActorCard key={actor.id} actor={actor} onClick={() => setSelectedActor(actor)} />
          ))}
          {filtered.length === 0 && (
            <div className="col-span-full text-center py-16 text-[#7d92b0]">
              <Users className="w-12 h-12 mx-auto mb-3 text-[#3d5068]" />
              <p>条件に一致するアクターが見つかりません</p>
            </div>
          )}
        </div>
      )}

      {/* Actor detail modal */}
      {selectedActor && (
        <ActorDetailModal actor={selectedActor} onClose={() => setSelectedActor(null)} />
      )}

      {/* Add actor modal */}
      {showAddModal && (
        <AddActorModal
          onClose={() => setShowAddModal(false)}
          onSubmit={data => addMutation.mutate(data)}
        />
      )}
    </div>
  )
}
