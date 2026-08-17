'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Bug, Search, X, ChevronRight, ExternalLink, AlertTriangle,
  Shield, Zap, Clock, CheckCircle, XCircle, Activity,
  TrendingUp, Eye, Package, Target, Info, RefreshCw,
  BarChart2, ArrowRight,
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ────────────────────────────────────────────────────────────────────

type Severity = 'critical' | 'high' | 'medium' | 'low'
type AttackVector = 'network' | 'adjacent' | 'local' | 'physical'
type AttackComplexity = 'low' | 'high'
type ExploitType = 'PoC' | 'Active' | 'Weaponized'
type ExploitStatus = 'none' | 'poc' | 'active' | 'weaponized'

interface AffectedProduct {
  vendor: string
  product: string
  versions: string[]
}

interface MitreMapping {
  technique_id: string
  technique_name: string
  tactic: string
}

interface CVEDetail {
  id: string
  title: string
  description: string
  cvss_score: number
  cvss_vector: string
  severity: Severity
  attack_vector: AttackVector
  attack_complexity: AttackComplexity
  published_date: string
  exploit_available: boolean
  exploit_type?: ExploitType
  exploit_published_date?: string
  exploit_sources?: string[]
  in_wild: boolean
  patch_available: boolean
  patch_info?: string
  workaround?: string
  vendor_advisory?: string
  affected_products: AffectedProduct[]
  mitre_techniques: MitreMapping[]
  related_cves: string[]
  first_exploited_date?: string
  threat_actor?: string
  campaign?: string
  affected_orgs_estimate?: number
  patch_released_date?: string
}

interface PriorityQueueItem {
  cve_id: string
  priority_score: number
  affected_assets: number
  exploit_status: ExploitStatus
  days_since_patch: number | null
  sla_deadline: string
  assignee: string
  status: 'open' | 'in_progress' | 'resolved'
}

// ── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_CVES: CVEDetail[] = [
  {
    id: 'CVE-2024-21762',
    title: 'FortiOS SSL VPN Out-of-Bound Write Vulnerability',
    description: 'An out-of-bounds write vulnerability in FortiOS SSL VPN allows unauthenticated remote attackers to execute arbitrary code or commands via specially crafted HTTP requests.',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'critical',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-02-08',
    exploit_available: true,
    exploit_type: 'Weaponized',
    exploit_published_date: '2024-02-10',
    exploit_sources: ['https://github.com/example/CVE-2024-21762', 'https://attackerkb.com/cve-2024-21762'],
    in_wild: true,
    patch_available: true,
    patch_info: 'Update to FortiOS 7.4.3, 7.2.7, 7.0.14, 6.4.15 or later',
    workaround: 'Disable SSL VPN or restrict access with IP whitelisting',
    vendor_advisory: 'FG-IR-24-015',
    affected_products: [
      { vendor: 'Fortinet', product: 'FortiOS', versions: ['7.4.0-7.4.2', '7.2.0-7.2.6', '7.0.0-7.0.13', '6.4.0-6.4.14'] },
      { vendor: 'Fortinet', product: 'FortiProxy', versions: ['7.4.0-7.4.2', '7.2.0-7.2.8'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', tactic: 'Execution' },
    ],
    related_cves: ['CVE-2023-27997', 'CVE-2022-42475'],
    first_exploited_date: '2024-02-10',
    threat_actor: 'Volt Typhoon',
    campaign: 'Critical Infrastructure Targeting',
    affected_orgs_estimate: 150000,
    patch_released_date: '2024-02-08',
  },
  {
    id: 'CVE-2024-3400',
    title: 'PAN-OS GlobalProtect OS Command Injection',
    description: 'A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software allows unauthenticated attackers to execute arbitrary code with root privileges on the firewall.',
    cvss_score: 10.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    severity: 'critical',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-04-12',
    exploit_available: true,
    exploit_type: 'Active',
    exploit_published_date: '2024-04-14',
    exploit_sources: ['https://unit42.paloaltonetworks.com/cve-2024-3400'],
    in_wild: true,
    patch_available: true,
    patch_info: 'Update to PAN-OS 11.1.2-h3, 11.0.4-h1, 10.2.9-h1, or later',
    workaround: 'Disable GlobalProtect portal and gateway if not needed',
    vendor_advisory: 'PAN-SA-2024-0006',
    affected_products: [
      { vendor: 'Palo Alto Networks', product: 'PAN-OS', versions: ['11.1.0-11.1.2', '11.0.0-11.0.4', '10.2.0-10.2.9'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { technique_id: 'T1068', technique_name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
    ],
    related_cves: ['CVE-2024-0012', 'CVE-2023-38203'],
    first_exploited_date: '2024-04-10',
    threat_actor: 'UTA0218',
    campaign: 'Operation MidnightEclipse',
    affected_orgs_estimate: 82000,
    patch_released_date: '2024-04-14',
  },
  {
    id: 'CVE-2024-1709',
    title: 'ConnectWise ScreenConnect Authentication Bypass',
    description: 'An authentication bypass vulnerability using an alternate path or channel in ConnectWise ScreenConnect allows unauthenticated users to access the system with administrative privileges.',
    cvss_score: 10.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    severity: 'critical',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-02-19',
    exploit_available: true,
    exploit_type: 'Weaponized',
    exploit_published_date: '2024-02-20',
    in_wild: true,
    patch_available: true,
    patch_info: 'Update to ScreenConnect 23.9.8 or later',
    vendor_advisory: 'ConnectWise Security Bulletin Feb 2024',
    affected_products: [
      { vendor: 'ConnectWise', product: 'ScreenConnect', versions: ['< 23.9.8'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { technique_id: 'T1078', technique_name: 'Valid Accounts', tactic: 'Defense Evasion' },
    ],
    related_cves: ['CVE-2024-1708'],
    first_exploited_date: '2024-02-21',
    threat_actor: 'Black Basta',
    campaign: 'Ransomware Campaign',
    affected_orgs_estimate: 200000,
    patch_released_date: '2024-02-19',
  },
  {
    id: 'CVE-2024-21887',
    title: 'Ivanti Connect Secure Command Injection',
    description: 'A command injection vulnerability in web components of Ivanti Connect Secure and Ivanti Policy Secure allows authenticated administrators to send specially crafted requests to execute arbitrary commands.',
    cvss_score: 9.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H',
    severity: 'critical',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-01-10',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Apply Ivanti security patches per advisory',
    vendor_advisory: 'Ivanti Advisory Jan 2024',
    affected_products: [
      { vendor: 'Ivanti', product: 'Connect Secure', versions: ['9.x', '22.x'] },
      { vendor: 'Ivanti', product: 'Policy Secure', versions: ['9.x', '22.x'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1059.004', technique_name: 'Unix Shell', tactic: 'Execution' },
    ],
    related_cves: ['CVE-2023-46805', 'CVE-2024-21888'],
    first_exploited_date: '2024-01-10',
    threat_actor: 'UNC5221',
    affected_orgs_estimate: 50000,
    patch_released_date: '2024-01-31',
  },
  {
    id: 'CVE-2024-38112',
    title: 'Windows MSHTML Platform Spoofing Vulnerability',
    description: 'A spoofing vulnerability in Windows MSHTML Platform allows attackers to execute arbitrary code via a specially crafted file, requiring user interaction.',
    cvss_score: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H',
    severity: 'high',
    attack_vector: 'network',
    attack_complexity: 'high',
    published_date: '2024-07-09',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Apply July 2024 Patch Tuesday update KB5040434',
    vendor_advisory: 'MSRC-ADV-2024-0014',
    affected_products: [
      { vendor: 'Microsoft', product: 'Windows 10', versions: ['21H2', '22H2'] },
      { vendor: 'Microsoft', product: 'Windows 11', versions: ['21H2', '22H2', '23H2'] },
      { vendor: 'Microsoft', product: 'Windows Server', versions: ['2019', '2022'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1566', technique_name: 'Phishing', tactic: 'Initial Access' },
      { technique_id: 'T1204', technique_name: 'User Execution', tactic: 'Execution' },
    ],
    related_cves: ['CVE-2024-30040', 'CVE-2024-38080'],
    first_exploited_date: '2024-06-15',
    affected_orgs_estimate: 800000,
    patch_released_date: '2024-07-09',
  },
  {
    id: 'CVE-2024-6387',
    title: 'OpenSSH regreSSHion Remote Code Execution',
    description: 'A signal handler race condition in OpenSSH\'s server (sshd) allows unauthenticated remote code execution as root on glibc-based Linux systems. This is a regression of CVE-2006-5051.',
    cvss_score: 8.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'high',
    attack_vector: 'network',
    attack_complexity: 'high',
    published_date: '2024-07-01',
    exploit_available: true,
    exploit_type: 'PoC',
    exploit_published_date: '2024-07-02',
    in_wild: false,
    patch_available: true,
    patch_info: 'Update to OpenSSH 9.8p1 or apply vendor patches',
    workaround: 'Set LoginGraceTime to 0 in sshd_config (mitigates but causes DoS risk)',
    vendor_advisory: 'OpenSSH Security Advisory',
    affected_products: [
      { vendor: 'OpenBSD', product: 'OpenSSH', versions: ['8.5p1 - 9.7p1'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1210', technique_name: 'Exploitation of Remote Services', tactic: 'Lateral Movement' },
    ],
    related_cves: ['CVE-2006-5051', 'CVE-2008-4109'],
    patch_released_date: '2024-07-01',
  },
  {
    id: 'CVE-2024-21413',
    title: 'Microsoft Outlook Remote Code Execution Vulnerability',
    description: 'A remote code execution vulnerability in Microsoft Outlook allows attackers to execute arbitrary code by sending a specially crafted email, bypassing the Protected View.',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'critical',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-02-13',
    exploit_available: true,
    exploit_type: 'PoC',
    in_wild: false,
    patch_available: true,
    patch_info: 'Apply February 2024 Patch Tuesday updates',
    vendor_advisory: 'MSRC-CVE-2024-21413',
    affected_products: [
      { vendor: 'Microsoft', product: 'Outlook 2016', versions: ['All'] },
      { vendor: 'Microsoft', product: 'Microsoft 365 Apps', versions: ['All'] },
      { vendor: 'Microsoft', product: 'Office LTSC 2021', versions: ['All'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1566.001', technique_name: 'Spearphishing Attachment', tactic: 'Initial Access' },
    ],
    related_cves: ['CVE-2024-30103', 'CVE-2023-23397'],
    patch_released_date: '2024-02-13',
  },
  {
    id: 'CVE-2024-0519',
    title: 'Google Chrome V8 Out-of-Bounds Memory Access',
    description: 'An out-of-bounds memory access vulnerability in the V8 JavaScript engine in Google Chrome allows a remote attacker to potentially exploit heap corruption via a crafted HTML page.',
    cvss_score: 8.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
    severity: 'high',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-01-16',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Update Chrome to version 120.0.6099.224 or later',
    vendor_advisory: 'Chrome Stable Channel Update 2024-01-16',
    affected_products: [
      { vendor: 'Google', product: 'Chrome', versions: ['< 120.0.6099.224'] },
      { vendor: 'Microsoft', product: 'Edge', versions: ['< 120.0.2210.133'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1189', technique_name: 'Drive-by Compromise', tactic: 'Initial Access' },
    ],
    related_cves: ['CVE-2024-0517', 'CVE-2024-0518'],
    first_exploited_date: '2024-01-10',
    affected_orgs_estimate: 3000000,
    patch_released_date: '2024-01-16',
  },
  {
    id: 'CVE-2024-30078',
    title: 'Windows Wi-Fi Driver Remote Code Execution',
    description: 'A remote code execution vulnerability in the Windows Wi-Fi Driver allows an unauthenticated attacker within Wi-Fi range to execute code on the affected system.',
    cvss_score: 8.8,
    cvss_vector: 'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'high',
    attack_vector: 'adjacent',
    attack_complexity: 'low',
    published_date: '2024-06-11',
    exploit_available: false,
    in_wild: false,
    patch_available: true,
    patch_info: 'Apply June 2024 Patch Tuesday updates',
    vendor_advisory: 'MSRC-CVE-2024-30078',
    affected_products: [
      { vendor: 'Microsoft', product: 'Windows 10', versions: ['21H2', '22H2'] },
      { vendor: 'Microsoft', product: 'Windows 11', versions: ['22H2', '23H2'] },
      { vendor: 'Microsoft', product: 'Windows Server', versions: ['2019', '2022'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1210', technique_name: 'Exploitation of Remote Services', tactic: 'Lateral Movement' },
    ],
    related_cves: [],
    patch_released_date: '2024-06-11',
  },
  {
    id: 'CVE-2024-23113',
    title: 'Fortinet FortiOS Format String Vulnerability',
    description: 'A format string vulnerability in Fortinet\'s fgfmd daemon allows a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted requests.',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'critical',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-02-08',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Update to FortiOS 7.4.3, 7.2.7 or later',
    vendor_advisory: 'FG-IR-24-029',
    affected_products: [
      { vendor: 'Fortinet', product: 'FortiOS', versions: ['7.0.0-7.0.13', '7.2.0-7.2.6', '7.4.0-7.4.2'] },
      { vendor: 'Fortinet', product: 'FortiPAM', versions: ['1.2.0', '1.1.x', '1.0.x'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    ],
    related_cves: ['CVE-2024-21762'],
    first_exploited_date: '2024-03-15',
    affected_orgs_estimate: 87000,
    patch_released_date: '2024-02-08',
  },
  {
    id: 'CVE-2024-26234',
    title: 'Windows Proxy Driver Spoofing Vulnerability',
    description: 'A spoofing vulnerability in a Windows Proxy Driver allows an authorized attacker to elevate privileges locally.',
    cvss_score: 6.7,
    cvss_vector: 'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H',
    severity: 'medium',
    attack_vector: 'local',
    attack_complexity: 'high',
    published_date: '2024-04-09',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Apply April 2024 Patch Tuesday updates',
    vendor_advisory: 'MSRC-CVE-2024-26234',
    affected_products: [
      { vendor: 'Microsoft', product: 'Windows 10', versions: ['All supported'] },
      { vendor: 'Microsoft', product: 'Windows 11', versions: ['All supported'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1068', technique_name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
    ],
    related_cves: ['CVE-2024-21338'],
    first_exploited_date: '2024-03-01',
    affected_orgs_estimate: 500000,
    patch_released_date: '2024-04-09',
  },
  {
    id: 'CVE-2024-38021',
    title: 'Microsoft Outlook Remote Code Execution (Zero-Click)',
    description: 'A zero-click remote code execution vulnerability in Microsoft Outlook allows an attacker to execute code without any user interaction when a specially crafted email is received.',
    cvss_score: 8.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'high',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-07-09',
    exploit_available: false,
    in_wild: false,
    patch_available: true,
    patch_info: 'Apply July 2024 Patch Tuesday updates',
    vendor_advisory: 'MSRC-CVE-2024-38021',
    affected_products: [
      { vendor: 'Microsoft', product: 'Outlook 2016', versions: ['All'] },
      { vendor: 'Microsoft', product: 'Microsoft 365 Apps', versions: ['All'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1566', technique_name: 'Phishing', tactic: 'Initial Access' },
    ],
    related_cves: ['CVE-2024-21413'],
    patch_released_date: '2024-07-09',
  },
  {
    id: 'CVE-2024-29988',
    title: 'Microsoft SmartScreen Prompt Security Feature Bypass',
    description: 'A security feature bypass vulnerability in Microsoft SmartScreen allows an attacker to circumvent the Mark of the Web protection.',
    cvss_score: 8.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
    severity: 'high',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-04-09',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Apply April 2024 Patch Tuesday updates',
    vendor_advisory: 'MSRC-CVE-2024-29988',
    affected_products: [
      { vendor: 'Microsoft', product: 'Windows Defender SmartScreen', versions: ['All'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1553.005', technique_name: 'Mark-of-the-Web Bypass', tactic: 'Defense Evasion' },
    ],
    related_cves: ['CVE-2024-26234', 'CVE-2024-21412'],
    first_exploited_date: '2024-03-20',
    affected_orgs_estimate: 600000,
    patch_released_date: '2024-04-09',
  },
  {
    id: 'CVE-2024-4978',
    title: 'JAVS Viewer Backdoor Supply Chain Attack',
    description: 'A backdoor in JAVS Viewer (Justice AV Solutions) software installer allows remote attackers to execute arbitrary code. This is a supply chain attack targeting court recording systems.',
    cvss_score: 8.7,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H',
    severity: 'high',
    attack_vector: 'network',
    attack_complexity: 'high',
    published_date: '2024-05-23',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Uninstall all versions and reinstall from official site',
    vendor_advisory: 'JAVS Security Advisory May 2024',
    affected_products: [
      { vendor: 'JAVS', product: 'Viewer', versions: ['8.3.7'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1195.002', technique_name: 'Compromise Software Supply Chain', tactic: 'Initial Access' },
      { technique_id: 'T1059.003', technique_name: 'Windows Command Shell', tactic: 'Execution' },
    ],
    related_cves: [],
    first_exploited_date: '2024-03-01',
    threat_actor: 'Lazarus Group',
    affected_orgs_estimate: 10000,
    patch_released_date: '2024-05-23',
  },
  {
    id: 'CVE-2024-27198',
    title: 'JetBrains TeamCity Authentication Bypass',
    description: 'An authentication bypass vulnerability in JetBrains TeamCity allows unauthenticated attackers to access the TeamCity server with administrator privileges.',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'critical',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-03-04',
    exploit_available: true,
    exploit_type: 'Weaponized',
    exploit_published_date: '2024-03-05',
    in_wild: true,
    patch_available: true,
    patch_info: 'Update to TeamCity 2023.11.4 or later',
    vendor_advisory: 'JetBrains Security Advisory 2024-001',
    affected_products: [
      { vendor: 'JetBrains', product: 'TeamCity', versions: ['< 2023.11.4'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { technique_id: 'T1078', technique_name: 'Valid Accounts', tactic: 'Persistence' },
    ],
    related_cves: ['CVE-2024-27199', 'CVE-2023-42793'],
    first_exploited_date: '2024-03-06',
    threat_actor: 'APT29',
    campaign: 'Software Development Pipeline Compromise',
    affected_orgs_estimate: 30000,
    patch_released_date: '2024-03-04',
  },
  {
    id: 'CVE-2024-20399',
    title: 'Cisco NX-OS Software CLI Command Injection',
    description: 'A vulnerability in the CLI of Cisco NX-OS Software allows authenticated, local attackers with NX-OS device management access to execute arbitrary OS commands with root privileges.',
    cvss_score: 6.0,
    cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N',
    severity: 'medium',
    attack_vector: 'local',
    attack_complexity: 'low',
    published_date: '2024-07-01',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Apply Cisco Security Advisory cisco-sa-nxos-cmd-injection-xD9eeX',
    vendor_advisory: 'cisco-sa-nxos-cmd-injection-xD9eeX',
    affected_products: [
      { vendor: 'Cisco', product: 'Nexus 3000 Series', versions: ['All'] },
      { vendor: 'Cisco', product: 'Nexus 9000 Series', versions: ['All'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', tactic: 'Execution' },
    ],
    related_cves: ['CVE-2024-20411'],
    first_exploited_date: '2024-04-01',
    threat_actor: 'Velvet Ant',
    affected_orgs_estimate: 12000,
    patch_released_date: '2024-07-01',
  },
  {
    id: 'CVE-2024-24919',
    title: 'Check Point Security Gateway Information Disclosure',
    description: 'A potentially sensitive information disclosure vulnerability in Check Point Security Gateway products, which could allow an attacker to access information on Gateways connected to the internet with remote access VPN.',
    cvss_score: 8.6,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
    severity: 'high',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-05-28',
    exploit_available: true,
    exploit_type: 'Weaponized',
    exploit_published_date: '2024-05-30',
    in_wild: true,
    patch_available: true,
    patch_info: 'Apply hotfix provided by Check Point',
    vendor_advisory: 'Check Point Advisory May 2024',
    affected_products: [
      { vendor: 'Check Point', product: 'CloudGuard Network', versions: ['All'] },
      { vendor: 'Check Point', product: 'Quantum Maestro', versions: ['All'] },
      { vendor: 'Check Point', product: 'Quantum Security Gateways', versions: ['R77.20 and above'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1552', technique_name: 'Unsecured Credentials', tactic: 'Credential Access' },
    ],
    related_cves: [],
    first_exploited_date: '2024-05-30',
    affected_orgs_estimate: 25000,
    patch_released_date: '2024-05-28',
  },
  {
    id: 'CVE-2024-37085',
    title: 'VMware ESXi Authentication Bypass',
    description: 'An authentication bypass vulnerability in VMware ESXi allows domain-joined ESXi hypervisors to be compromised. A malicious actor with sufficient Active Directory permissions could gain full access.',
    cvss_score: 7.2,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
    severity: 'high',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-07-25',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Apply VMware Security Advisory VMSA-2024-0013',
    vendor_advisory: 'VMSA-2024-0013',
    affected_products: [
      { vendor: 'VMware', product: 'ESXi 8.0', versions: ['All'] },
      { vendor: 'VMware', product: 'ESXi 7.0', versions: ['All'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { technique_id: 'T1484', technique_name: 'Domain Policy Modification', tactic: 'Defense Evasion' },
    ],
    related_cves: ['CVE-2024-22245'],
    first_exploited_date: '2024-07-20',
    threat_actor: 'Storm-0506',
    campaign: 'Akira Ransomware',
    affected_orgs_estimate: 20000,
    patch_released_date: '2024-07-25',
  },
  {
    id: 'CVE-2024-43461',
    title: 'Windows MSHTML Platform Spoofing Vulnerability',
    description: 'A spoofing vulnerability in the Windows MSHTML Platform allows attackers to hide the true extension of malicious files, deceiving users into executing harmful content.',
    cvss_score: 8.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
    severity: 'high',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-09-10',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Apply September 2024 Patch Tuesday updates',
    vendor_advisory: 'MSRC-CVE-2024-43461',
    affected_products: [
      { vendor: 'Microsoft', product: 'Windows 10', versions: ['All supported'] },
      { vendor: 'Microsoft', product: 'Windows 11', versions: ['All supported'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1036', technique_name: 'Masquerading', tactic: 'Defense Evasion' },
      { technique_id: 'T1204', technique_name: 'User Execution', tactic: 'Execution' },
    ],
    related_cves: ['CVE-2024-38112'],
    first_exploited_date: '2024-07-01',
    threat_actor: 'Void Banshee',
    affected_orgs_estimate: 400000,
    patch_released_date: '2024-09-10',
  },
  {
    id: 'CVE-2024-47575',
    title: 'Fortinet FortiManager Missing Authentication',
    description: 'A missing authentication for critical function vulnerability in Fortinet FortiManager allows a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted requests.',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'critical',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-10-23',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Update to FortiManager 7.6.1, 7.4.5, 7.2.8, 7.0.13, 6.4.15 or later',
    vendor_advisory: 'FG-IR-24-423',
    affected_products: [
      { vendor: 'Fortinet', product: 'FortiManager', versions: ['7.6.0', '7.4.0-7.4.4', '7.2.0-7.2.7', '7.0.0-7.0.12'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { technique_id: 'T1059', technique_name: 'Command and Scripting Interpreter', tactic: 'Execution' },
    ],
    related_cves: ['CVE-2024-21762', 'CVE-2024-23113'],
    first_exploited_date: '2024-10-01',
    threat_actor: 'UNC5820',
    campaign: 'FortiJump',
    affected_orgs_estimate: 50000,
    patch_released_date: '2024-10-23',
  },
  {
    id: 'CVE-2024-28986',
    title: 'SolarWinds Web Help Desk Java Deserialization RCE',
    description: 'A Java deserialization vulnerability in SolarWinds Web Help Desk allows an unauthenticated attacker to execute remote code. This may require authentication in some deployment configurations.',
    cvss_score: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity: 'critical',
    attack_vector: 'network',
    attack_complexity: 'low',
    published_date: '2024-08-13',
    exploit_available: true,
    exploit_type: 'Active',
    in_wild: true,
    patch_available: true,
    patch_info: 'Update to Web Help Desk 12.8.3 Hotfix 2 or later',
    vendor_advisory: 'SolarWinds Security Advisory Aug 2024',
    affected_products: [
      { vendor: 'SolarWinds', product: 'Web Help Desk', versions: ['< 12.8.3 HF2'] },
    ],
    mitre_techniques: [
      { technique_id: 'T1190', technique_name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    ],
    related_cves: ['CVE-2024-28987'],
    first_exploited_date: '2024-08-14',
    affected_orgs_estimate: 8000,
    patch_released_date: '2024-08-13',
  },
]

const MOCK_PRIORITY_QUEUE: PriorityQueueItem[] = m(MOCK_CVES).filter(c => c.cvss_score >= 7).slice(0, 10).map((c, i) => {
  const exploitScore = c.exploit_type === 'Weaponized' ? 1 : c.exploit_type === 'Active' ? 0.8 : c.exploit_type === 'PoC' ? 0.5 : 0
  const exposure = Math.random() * 100
  const priorityScore = Math.round((c.cvss_score * 0.4) + (exploitScore * 30) + (exposure * 0.3))
  return {
    cve_id: c.id,
    priority_score: priorityScore,
    affected_assets: Math.floor(Math.random() * 500) + 10,
    exploit_status: (c.exploit_type === 'Weaponized' ? 'weaponized' : c.exploit_type === 'Active' ? 'active' : c.exploit_type === 'PoC' ? 'poc' : 'none') as ExploitStatus,
    days_since_patch: c.patch_available ? Math.floor(Math.random() * 60) + 1 : null,
    sla_deadline: new Date(Date.now() + (i + 1) * 3 * 86400000).toISOString().split('T')[0],
    assignee: ['田中', '鈴木', '佐藤', '高橋', '伊藤'][i % 5],
    status: (i < 3 ? 'in_progress' : 'open') as 'open' | 'in_progress' | 'resolved',
  }
}).sort((a, b) => b.priority_score - a.priority_score)

// ── Helpers ──────────────────────────────────────────────────────────────────

const SEV_CONFIG: Record<Severity, { label: string; cls: string; score: string }> = {
  critical: { label: 'Critical', cls: 'bg-red-900/60 border-red-700 text-red-300', score: 'text-red-400' },
  high: { label: 'High', cls: 'bg-orange-900/60 border-orange-700 text-orange-300', score: 'text-orange-400' },
  medium: { label: 'Medium', cls: 'bg-yellow-900/60 border-yellow-700 text-yellow-300', score: 'text-yellow-400' },
  low: { label: 'Low', cls: 'bg-blue-900/60 border-blue-700 text-blue-300', score: 'text-blue-400' },
}

const AV_CONFIG: Record<AttackVector, { label: string; cls: string }> = {
  network: { label: 'Network', cls: 'bg-purple-900/40 border-purple-700 text-purple-300' },
  adjacent: { label: 'Adjacent', cls: 'bg-blue-900/40 border-blue-700 text-blue-300' },
  local: { label: 'Local', cls: 'bg-green-900/40 border-green-700 text-green-300' },
  physical: { label: 'Physical', cls: 'bg-gray-900/40 border-gray-700 text-gray-300' },
}

const EXPLOIT_TYPE_CONFIG: Record<ExploitType, { cls: string }> = {
  PoC: { cls: 'bg-yellow-900/60 border-yellow-700 text-yellow-300' },
  Active: { cls: 'bg-orange-900/60 border-orange-700 text-orange-300' },
  Weaponized: { cls: 'bg-red-900/60 border-red-700 text-red-300' },
}

const EXPLOIT_STATUS_CONFIG: Record<ExploitStatus, { label: string; cls: string }> = {
  none: { label: 'なし', cls: 'bg-gray-900/40 border-gray-700 text-gray-300' },
  poc: { label: 'PoC', cls: 'bg-yellow-900/60 border-yellow-700 text-yellow-300' },
  active: { label: 'Active', cls: 'bg-orange-900/60 border-orange-700 text-orange-300' },
  weaponized: { label: 'Weaponized', cls: 'bg-red-900/60 border-red-700 text-red-300' },
}

function cvssColor(score: number) {
  if (score >= 9) return 'text-red-400'
  if (score >= 7) return 'text-orange-400'
  if (score >= 4) return 'text-yellow-400'
  return 'text-blue-400'
}

function Badge({ children, cls }: { children: React.ReactNode; cls: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm border text-xs font-medium ${cls}`}>
      {children}
    </span>
  )
}

// ── CVE Detail Modal ─────────────────────────────────────────────────────────

function CVEDetailModal({ cve, onClose }: { cve: CVEDetail; onClose: () => void }) {
  const [activeSection, setActiveSection] = useState<'overview' | 'products' | 'exploit' | 'patch' | 'timeline' | 'mitre'>('overview')
  const sev = SEV_CONFIG[cve.severity]
  const av = AV_CONFIG[cve.attack_vector]

  // CVSS score breakdown bars
  const scoreComponents = [
    { label: 'Attack Vector', value: cve.attack_vector === 'network' ? 100 : cve.attack_vector === 'adjacent' ? 67 : cve.attack_vector === 'local' ? 33 : 10 },
    { label: 'Attack Complexity', value: cve.attack_complexity === 'low' ? 100 : 50 },
    { label: 'CVSS Base Score', value: (cve.cvss_score / 10) * 100 },
    { label: 'Exploitability', value: cve.exploit_available ? (cve.exploit_type === 'Weaponized' ? 100 : cve.exploit_type === 'Active' ? 75 : 50) : 10 },
  ]

  const timelineEvents = [
    { label: 'CVE Published', date: cve.published_date, icon: Info, color: 'bg-blue-500' },
    ...(cve.exploit_published_date ? [{ label: 'Exploit Released', date: cve.exploit_published_date, icon: Zap, color: 'bg-orange-500' }] : []),
    ...(cve.first_exploited_date ? [{ label: 'First Exploited in Wild', date: cve.first_exploited_date, icon: AlertTriangle, color: 'bg-red-500' }] : []),
    ...(cve.patch_released_date ? [{ label: 'Patch Released', date: cve.patch_released_date, icon: CheckCircle, color: 'bg-green-500' }] : []),
  ].sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime())

  const sections = ['overview', 'products', 'exploit', 'patch', 'timeline', 'mitre'] as const
  const sectionLabels: Record<typeof sections[number], string> = {
    overview: '概要', products: '影響製品', exploit: 'エクスプロイト', patch: 'パッチ情報', timeline: 'タイムライン', mitre: 'MITRE ATT&CK',
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-5xl max-h-[92vh] flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start gap-4 p-6 border-b border-falcon-border">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <span className="font-mono text-falcon-red text-lg font-bold">{cve.id}</span>
              <Badge cls={sev.cls}>{sev.label}</Badge>
              <span className={`text-2xl font-bold ${cvssColor(cve.cvss_score)}`}>{cve.cvss_score.toFixed(1)}</span>
              {cve.in_wild && <Badge cls="bg-red-900/60 border-red-700 text-red-300 animate-pulse">野外悪用中</Badge>}
              {cve.exploit_available && cve.exploit_type && <Badge cls={EXPLOIT_TYPE_CONFIG[cve.exploit_type].cls}>{cve.exploit_type}</Badge>}
            </div>
            <h2 className="text-white font-semibold text-lg leading-tight">{cve.title}</h2>
            <p className="text-falcon-muted text-xs mt-1 font-mono">{cve.cvss_vector}</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <a href={`/assets/vulnerabilities?cve=${cve.id}`} className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-[#1a2540] border border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-red text-sm transition-colors">
              <Eye className="w-3.5 h-3.5" /> 影響資産を確認
            </a>
            <button onClick={onClose} className="p-2 rounded-sm hover:bg-falcon-border text-falcon-muted hover:text-white transition-colors">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Section tabs */}
        <div className="flex gap-1 px-6 pt-3 border-b border-falcon-border">
          {sections.map(s => (
            <button
              key={s}
              onClick={() => setActiveSection(s)}
              className={`px-3 py-2 text-sm font-medium rounded-t transition-colors ${activeSection === s ? 'text-white border-b-2 border-falcon-red' : 'text-falcon-muted hover:text-white'}`}
            >
              {sectionLabels[s]}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {activeSection === 'overview' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-falcon-muted text-xs uppercase tracking-wider mb-2">説明</h3>
                <p className="text-white text-sm leading-relaxed">{cve.description}</p>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                  <p className="text-falcon-muted text-xs mb-1">Attack Vector</p>
                  <Badge cls={av.cls}>{av.label}</Badge>
                </div>
                <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                  <p className="text-falcon-muted text-xs mb-1">Attack Complexity</p>
                  <Badge cls={cve.attack_complexity === 'low' ? 'bg-red-900/40 border-red-700 text-red-300' : 'bg-green-900/40 border-green-700 text-green-300'}>
                    {cve.attack_complexity === 'low' ? 'Low' : 'High'}
                  </Badge>
                </div>
                <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                  <p className="text-falcon-muted text-xs mb-1">公開日</p>
                  <p className="text-white text-sm">{cve.published_date}</p>
                </div>
                <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                  <p className="text-falcon-muted text-xs mb-1">影響製品数</p>
                  <p className="text-white text-sm font-bold">{cve.affected_products.reduce((sum, p) => sum + p.versions.length, 0)}</p>
                </div>
              </div>
              <div>
                <h3 className="text-falcon-muted text-xs uppercase tracking-wider mb-3">スコア内訳</h3>
                <div className="space-y-3">
                  {scoreComponents.map(c => (
                    <div key={c.label}>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-falcon-muted">{c.label}</span>
                        <span className="text-white">{c.value}%</span>
                      </div>
                      <div className="h-2 bg-[#0a1628] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${c.value}%`, background: c.value >= 80 ? '#e8002d' : c.value >= 50 ? '#f97316' : '#eab308' }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              {cve.related_cves.length > 0 && (
                <div>
                  <h3 className="text-falcon-muted text-xs uppercase tracking-wider mb-2">関連CVE</h3>
                  <div className="flex flex-wrap gap-2">
                    {cve.related_cves.map(id => (
                      <span key={id} className="font-mono text-falcon-red text-sm bg-red-900/10 border border-red-900/30 rounded-sm px-2 py-1">{id}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeSection === 'products' && (
            <div className="space-y-4">
              {cve.affected_products.map((p, i) => (
                <div key={i} className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                  <div className="flex items-center gap-2 mb-3">
                    <Package className="w-4 h-4 text-falcon-red" />
                    <span className="text-white font-semibold">{p.vendor}</span>
                    <ChevronRight className="w-3.5 h-3.5 text-falcon-subtle" />
                    <span className="text-falcon-muted">{p.product}</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {p.versions.map((v, j) => (
                      <span key={j} className="font-mono text-xs bg-[#0a1628] border border-falcon-border text-falcon-muted rounded-sm px-2 py-1">{v}</span>
                    ))}
                  </div>
                </div>
              ))}
              {cve.affected_orgs_estimate && (
                <div className="bg-orange-900/20 border border-orange-800/40 rounded-lg p-4">
                  <p className="text-orange-300 text-sm">推定影響組織数: <span className="font-bold text-orange-200">{(cve.affected_orgs_estimate ?? 0).toLocaleString()}</span></p>
                </div>
              )}
            </div>
          )}

          {activeSection === 'exploit' && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                  <p className="text-falcon-muted text-xs mb-2">エクスプロイト状況</p>
                  {cve.exploit_available && cve.exploit_type
                    ? <Badge cls={EXPLOIT_TYPE_CONFIG[cve.exploit_type].cls}>{cve.exploit_type}</Badge>
                    : <Badge cls="bg-gray-900/40 border-gray-700 text-gray-300">なし</Badge>
                  }
                </div>
                <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                  <p className="text-falcon-muted text-xs mb-2">野外での悪用</p>
                  {cve.in_wild
                    ? <Badge cls="bg-red-900/60 border-red-700 text-red-300 animate-pulse">確認済み</Badge>
                    : <Badge cls="bg-green-900/40 border-green-700 text-green-300">未確認</Badge>
                  }
                </div>
                {cve.exploit_published_date && (
                  <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                    <p className="text-falcon-muted text-xs mb-2">エクスプロイト公開日</p>
                    <p className="text-white text-sm">{cve.exploit_published_date}</p>
                  </div>
                )}
                {cve.first_exploited_date && (
                  <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                    <p className="text-falcon-muted text-xs mb-2">野外初確認日</p>
                    <p className="text-white text-sm">{cve.first_exploited_date}</p>
                  </div>
                )}
              </div>
              {cve.threat_actor && (
                <div className="bg-red-900/20 border border-red-800/40 rounded-lg p-4">
                  <p className="text-falcon-muted text-xs mb-1">脅威アクター</p>
                  <p className="text-red-300 font-semibold">{cve.threat_actor}</p>
                  {cve.campaign && <p className="text-falcon-muted text-sm mt-1">キャンペーン: <span className="text-white">{cve.campaign}</span></p>}
                </div>
              )}
              {cve.exploit_sources && cve.exploit_sources.length > 0 && (
                <div>
                  <h3 className="text-falcon-muted text-xs uppercase tracking-wider mb-2">参照URL</h3>
                  <div className="space-y-2">
                    {cve.exploit_sources.map((url, i) => (
                      <div key={i} className="flex items-center gap-2 bg-[#070d19] border border-falcon-border rounded-sm p-3">
                        <ExternalLink className="w-3.5 h-3.5 text-falcon-subtle shrink-0" />
                        <span className="text-falcon-muted text-sm font-mono break-all">{url}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeSection === 'patch' && (
            <div className="space-y-4">
              <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                <p className="text-falcon-muted text-xs mb-2">パッチ状況</p>
                {cve.patch_available
                  ? <Badge cls="bg-green-900/40 border-green-700 text-green-300">利用可能</Badge>
                  : <Badge cls="bg-red-900/60 border-red-700 text-red-300">未提供</Badge>
                }
              </div>
              {cve.patch_info && (
                <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                  <p className="text-falcon-muted text-xs mb-2">パッチ情報</p>
                  <p className="text-white text-sm">{cve.patch_info}</p>
                </div>
              )}
              {cve.workaround && (
                <div className="bg-yellow-900/20 border border-yellow-800/40 rounded-lg p-4">
                  <p className="text-yellow-400 text-xs font-semibold mb-2">ワークアラウンド</p>
                  <p className="text-yellow-200 text-sm">{cve.workaround}</p>
                </div>
              )}
              {cve.vendor_advisory && (
                <div className="bg-[#070d19] rounded-lg p-4 border border-falcon-border">
                  <p className="text-falcon-muted text-xs mb-2">ベンダーアドバイザリ</p>
                  <p className="text-white text-sm font-mono">{cve.vendor_advisory}</p>
                </div>
              )}
            </div>
          )}

          {activeSection === 'timeline' && (
            <div className="relative pl-8">
              <div className="absolute left-4 top-0 bottom-0 w-px bg-falcon-border" />
              {timelineEvents.map((ev, i) => {
                const Icon = ev.icon
                return (
                  <div key={i} className="relative mb-8 last:mb-0">
                    <div className={`absolute -left-4 w-8 h-8 rounded-full ${ev.color} flex items-center justify-center -translate-x-1/2`}>
                      <Icon className="w-4 h-4 text-white" />
                    </div>
                    <div className="bg-[#070d19] border border-falcon-border rounded-lg p-4 ml-4">
                      <p className="text-white font-semibold text-sm">{ev.label}</p>
                      <p className="text-falcon-muted text-sm mt-0.5">{ev.date}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {activeSection === 'mitre' && (
            <div className="space-y-3">
              {cve.mitre_techniques.length === 0 && (
                <p className="text-falcon-muted text-sm">マッピングなし</p>
              )}
              {cve.mitre_techniques.map((t, i) => (
                <div key={i} className="bg-[#070d19] rounded-lg p-4 border border-falcon-border flex items-center gap-4">
                  <div className="shrink-0 bg-red-900/20 border border-red-900/30 rounded-lg p-3">
                    <Target className="w-5 h-5 text-falcon-red" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-falcon-red text-sm font-bold">{t.technique_id}</span>
                      <Badge cls="bg-purple-900/40 border-purple-700 text-purple-300">{t.tactic}</Badge>
                    </div>
                    <p className="text-white text-sm mt-0.5">{t.technique_name}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function VulnerabilityIntelligencePage() {
  const [activeTab, setActiveTab] = useState<'database' | 'exploits' | 'queue'>('database')
  const [cveSearch, setCveSearch] = useState('')
  const [selectedCVE, setSelectedCVE] = useState<CVEDetail | null>(null)
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'all'>('all')
  const [filterAV, setFilterAV] = useState<AttackVector | 'all'>('all')
  const [filterExploit, setFilterExploit] = useState<'all' | 'yes' | 'no'>('all')
  const [searchInput, setSearchInput] = useState('')

  const { data: cveData, isLoading } = useQuery<CVEDetail[]>({
    queryKey: ['cves'],
    queryFn: () => apiFetch('/api/v1/vulnerabilities/cves'),
    retry: false,
  })

  const cves = useMemo(() => cveData ?? m(MOCK_CVES), [cveData])
  const exploitedCves = useMemo(() => cves.filter(c => c.in_wild), [cves])

  const filteredCves = useMemo(() => {
    return cves.filter(c => {
      if (filterSeverity !== 'all' && c.severity !== filterSeverity) return false
      if (filterAV !== 'all' && c.attack_vector !== filterAV) return false
      if (filterExploit === 'yes' && !c.exploit_available) return false
      if (filterExploit === 'no' && c.exploit_available) return false
      if (searchInput) {
        const q = searchInput.toLowerCase()
        if (!c.id.toLowerCase().includes(q) && !c.title.toLowerCase().includes(q)) return false
      }
      return true
    })
  }, [cves, filterSeverity, filterAV, filterExploit, searchInput])

  const stats = useMemo(() => ({
    total: cves.length,
    inWild: cves.filter(c => c.in_wild).length,
    avgCvss: cves.length > 0 ? (cves.reduce((sum, c) => sum + (Number(c.cvss_score) || 0), 0) / cves.length).toFixed(1) : '0.0',
    critical: cves.filter(c => c.severity === 'critical').length,
  }), [cves])

  // Monthly exploit trend (mock)
  const monthlyTrend = [
    { month: 'Oct', count: 3 }, { month: 'Nov', count: 5 }, { month: 'Dec', count: 4 },
    { month: 'Jan', count: 7 }, { month: 'Feb', count: 9 }, { month: 'Mar', count: 6 },
  ]

  // Top targeted products (mock)
  const topProducts = [
    { name: 'Windows OS', count: 45 },
    { name: 'Fortinet FortiOS', count: 38 },
    { name: 'Microsoft Exchange', count: 30 },
    { name: 'Palo Alto PAN-OS', count: 25 },
    { name: 'VMware ESXi', count: 22 },
    { name: 'Ivanti Connect Secure', count: 18 },
    { name: 'Cisco NX-OS', count: 15 },
    { name: 'Chrome/Edge', count: 12 },
  ]
  const maxCount = Math.max(...topProducts.map(p => p.count))

  const handleCveSearch = () => {
    if (!cveSearch.trim()) return
    const found = cves.find(c => c.id.toLowerCase() === cveSearch.trim().toLowerCase())
    if (found) setSelectedCVE(found)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-red-900/30 border border-red-800/40 flex items-center justify-center">
            <Bug className="w-5 h-5 text-falcon-red" />
          </div>
          <div>
            <h1 className="text-white text-xl font-bold">脆弱性インテリジェンス</h1>
            <p className="text-falcon-muted text-sm">CVEデータベース・エクスプロイト分析・優先度管理</p>
          </div>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-falcon-surface border border-falcon-border rounded-lg text-falcon-muted hover:text-white hover:border-falcon-muted/50 transition-colors text-sm">
          <RefreshCw className="w-4 h-4" /> 更新
        </button>
      </div>

      {/* CVE Search Bar */}
      <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4 mb-6">
        <p className="text-falcon-muted text-xs uppercase tracking-wider mb-3">CVE検索</p>
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-falcon-subtle" />
            <input
              value={cveSearch}
              onChange={e => setCveSearch(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleCveSearch()}
              placeholder="CVE-YYYY-NNNNN を入力..."
              className="w-full bg-[#070d19] border border-falcon-border rounded-lg pl-10 pr-4 py-3 text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50 font-mono text-sm transition-colors"
            />
          </div>
          <button
            onClick={handleCveSearch}
            className="px-6 py-3 bg-falcon-red text-white rounded-lg font-semibold hover:bg-[#c0001f] transition-colors text-sm"
          >
            詳細検索
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: 'CVE追跡数', value: stats.total, icon: Bug, color: 'text-blue-400', bg: 'bg-blue-900/20 border-blue-800/40' },
          { label: '野外悪用確認', value: stats.inWild, icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-900/20 border-red-800/40' },
          { label: '平均CVSSスコア', value: stats.avgCvss, icon: Activity, color: 'text-orange-400', bg: 'bg-orange-900/20 border-orange-800/40' },
          { label: 'Critical件数', value: stats.critical, icon: Zap, color: 'text-yellow-400', bg: 'bg-yellow-900/20 border-yellow-800/40' },
        ].map(s => {
          const Icon = s.icon
          return (
            <div key={s.label} className={`bg-falcon-surface border rounded-xl p-4 ${s.bg}`}>
              <div className="flex items-center gap-2 mb-2">
                <Icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-falcon-muted text-xs">{s.label}</span>
              </div>
              <p className={`text-3xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          )
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {([
          { key: 'database', label: 'CVEデータベース' },
          { key: 'exploits', label: 'エクスプロイト分析' },
          { key: 'queue', label: '優先度キュー' },
        ] as const).map(t => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            className={`px-4 py-2 rounded-sm text-sm font-medium transition-colors ${activeTab === t.key ? 'bg-falcon-red text-white' : 'text-falcon-muted hover:text-white'}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── CVE Database Tab ── */}
      {activeTab === 'database' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3 bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-falcon-subtle" />
              <input
                value={searchInput}
                onChange={e => setSearchInput(e.target.value)}
                placeholder="CVE ID / タイトル検索..."
                className="bg-[#070d19] border border-falcon-border rounded-lg pl-9 pr-4 py-2 text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50 text-sm w-56 transition-colors"
              />
            </div>
            <select
              value={filterSeverity}
              onChange={e => setFilterSeverity(e.target.value as Severity | 'all')}
              className="bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-falcon-muted text-sm focus:outline-hidden focus:border-falcon-red/50"
            >
              <option value="all">全重要度</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select
              value={filterAV}
              onChange={e => setFilterAV(e.target.value as AttackVector | 'all')}
              className="bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-falcon-muted text-sm focus:outline-hidden focus:border-falcon-red/50"
            >
              <option value="all">全Attack Vector</option>
              <option value="network">Network</option>
              <option value="adjacent">Adjacent</option>
              <option value="local">Local</option>
              <option value="physical">Physical</option>
            </select>
            <select
              value={filterExploit}
              onChange={e => setFilterExploit(e.target.value as 'all' | 'yes' | 'no')}
              className="bg-[#070d19] border border-falcon-border rounded-lg px-3 py-2 text-falcon-muted text-sm focus:outline-hidden focus:border-falcon-red/50"
            >
              <option value="all">全エクスプロイト</option>
              <option value="yes">あり</option>
              <option value="no">なし</option>
            </select>
            <span className="ml-auto text-falcon-muted text-sm self-center">{filteredCves.length}件</span>
          </div>

          {/* Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['CVE ID', 'タイトル', 'CVSS', 'Attack Vector', '複雑度', '重要度', '公開日', 'エクスプロイト', '野外', 'パッチ', '製品数'].map(h => (
                      <th key={h} className="text-left text-falcon-muted text-xs font-medium uppercase tracking-wider px-4 py-3 whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-falcon-border">
                  {filteredCves.map(cve => {
                    const sev = SEV_CONFIG[cve.severity]
                    const av = AV_CONFIG[cve.attack_vector]
                    return (
                      <tr key={cve.id} className="hover:bg-[#0a1628] transition-colors">
                        <td className="px-4 py-3">
                          <button
                            onClick={() => setSelectedCVE(cve)}
                            className="font-mono text-falcon-red text-sm font-bold hover:underline whitespace-nowrap"
                          >
                            {cve.id}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <p className="text-white text-sm max-w-xs truncate">{cve.title}</p>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`font-bold text-sm ${cvssColor(cve.cvss_score)}`}>{cve.cvss_score.toFixed(1)}</span>
                        </td>
                        <td className="px-4 py-3"><Badge cls={av.cls}>{av.label}</Badge></td>
                        <td className="px-4 py-3">
                          <Badge cls={cve.attack_complexity === 'low' ? 'bg-red-900/40 border-red-700 text-red-300' : 'bg-green-900/40 border-green-700 text-green-300'}>
                            {cve.attack_complexity === 'low' ? 'Low' : 'High'}
                          </Badge>
                        </td>
                        <td className="px-4 py-3"><Badge cls={sev.cls}>{sev.label}</Badge></td>
                        <td className="px-4 py-3 text-falcon-muted text-sm whitespace-nowrap">{cve.published_date}</td>
                        <td className="px-4 py-3">
                          {cve.exploit_available
                            ? <Badge cls={`${cve.exploit_type ? EXPLOIT_TYPE_CONFIG[cve.exploit_type].cls : 'bg-orange-900/60 border-orange-700 text-orange-300'} ${cve.exploit_type === 'Weaponized' ? 'animate-pulse' : ''}`}>
                                {cve.exploit_type ?? 'あり'}
                              </Badge>
                            : <span className="text-falcon-subtle text-xs">—</span>
                          }
                        </td>
                        <td className="px-4 py-3">
                          {cve.in_wild
                            ? <span className="inline-block w-2 h-2 rounded-full bg-red-500 animate-pulse" title="野外悪用確認" />
                            : <span className="inline-block w-2 h-2 rounded-full bg-falcon-border" />
                          }
                        </td>
                        <td className="px-4 py-3">
                          {cve.patch_available
                            ? <CheckCircle className="w-4 h-4 text-green-400" />
                            : <XCircle className="w-4 h-4 text-red-400" />
                          }
                        </td>
                        <td className="px-4 py-3 text-falcon-muted text-sm">
                          {cve.affected_products.reduce((sum, p) => sum + p.versions.length, 0)}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Exploit Analysis Tab ── */}
      {activeTab === 'exploits' && (
        <div className="space-y-6">
          {/* Exploited in Wild List */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-falcon-border">
              <h2 className="text-white font-semibold flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-falcon-red" /> 野外悪用確認済みCVE ({exploitedCves.length}件)
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['CVE ID', 'タイトル', '初確認日', '脅威アクター', 'キャンペーン', '推定影響組織', 'CVSS', 'パッチ'].map(h => (
                      <th key={h} className="text-left text-falcon-muted text-xs font-medium uppercase tracking-wider px-4 py-3 whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-falcon-border">
                  {exploitedCves.map(cve => (
                    <tr key={cve.id} className="hover:bg-[#0a1628] transition-colors">
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedCVE(cve)} className="font-mono text-falcon-red text-sm font-bold hover:underline">
                          {cve.id}
                        </button>
                      </td>
                      <td className="px-4 py-3"><p className="text-white text-sm max-w-[200px] truncate">{cve.title}</p></td>
                      <td className="px-4 py-3 text-falcon-muted text-sm whitespace-nowrap">{cve.first_exploited_date ?? '—'}</td>
                      <td className="px-4 py-3">
                        {cve.threat_actor
                          ? <span className="text-red-300 text-sm font-medium">{cve.threat_actor}</span>
                          : <span className="text-falcon-subtle text-sm">不明</span>
                        }
                      </td>
                      <td className="px-4 py-3 text-falcon-muted text-sm">{cve.campaign ?? '—'}</td>
                      <td className="px-4 py-3">
                        {cve.affected_orgs_estimate
                          ? <span className="text-orange-300 text-sm font-medium">{(cve.affected_orgs_estimate ?? 0).toLocaleString()}</span>
                          : <span className="text-falcon-subtle text-sm">—</span>
                        }
                      </td>
                      <td className="px-4 py-3">
                        <span className={`font-bold text-sm ${cvssColor(cve.cvss_score)}`}>{cve.cvss_score.toFixed(1)}</span>
                      </td>
                      <td className="px-4 py-3">
                        {cve.patch_available
                          ? <CheckCircle className="w-4 h-4 text-green-400" />
                          : <XCircle className="w-4 h-4 text-red-400 animate-pulse" />
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Monthly Trend */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6">
              <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-falcon-red" /> エクスプロイトトレンド（月別）
              </h3>
              <div className="flex items-end gap-3 h-32">
                {monthlyTrend.map(m => {
                  const maxVal = Math.max(...monthlyTrend.map(x => x.count))
                  const pct = (m.count / maxVal) * 100
                  return (
                    <div key={m.month} className="flex-1 flex flex-col items-center gap-1">
                      <span className="text-falcon-muted text-xs">{m.count}</span>
                      <div className="w-full bg-[#070d19] rounded-t" style={{ height: `${pct}%`, minHeight: 4, background: `linear-gradient(to top, #e8002d, #ff4d4d)` }} />
                      <span className="text-falcon-subtle text-xs">{m.month}</span>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Top Targeted Products */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6">
              <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                <BarChart2 className="w-4 h-4 text-falcon-red" /> 標的製品 Top 8
              </h3>
              <div className="space-y-3">
                {topProducts.map(p => (
                  <div key={p.name}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-falcon-muted">{p.name}</span>
                      <span className="text-white">{p.count}</span>
                    </div>
                    <div className="h-2 bg-[#070d19] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{ width: `${(p.count / maxCount) * 100}%`, background: 'linear-gradient(to right, #e8002d, #ff4d4d)' }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Weaponization Timeline Scatter */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6">
            <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
              <Clock className="w-4 h-4 text-falcon-red" /> CVE公開からエクスプロイト化までの日数
            </h3>
            <div className="relative h-40 bg-[#070d19] rounded-lg border border-falcon-border overflow-hidden">
              {/* Axes labels */}
              <div className="absolute bottom-2 left-4 right-4 flex justify-between text-falcon-subtle text-xs">
                <span>0日</span><span>30日</span><span>60日</span><span>90日</span><span>120日+</span>
              </div>
              {/* Scatter dots */}
              {exploitedCves.filter(c => c.exploit_published_date).map((cve, i) => {
                const days = Math.min(Math.floor((new Date(cve.exploit_published_date!).getTime() - new Date(cve.published_date).getTime()) / 86400000), 120)
                const xPct = Math.max(2, Math.min(98, (days / 120) * 100))
                const yPct = 20 + (i % 5) * 14
                const color = cve.exploit_type === 'Weaponized' ? '#e8002d' : cve.exploit_type === 'Active' ? '#f97316' : '#eab308'
                return (
                  <div
                    key={cve.id}
                    title={`${cve.id}: ${days}日`}
                    className="absolute w-3 h-3 rounded-full cursor-pointer hover:scale-150 transition-transform"
                    style={{ left: `${xPct}%`, top: `${yPct}%`, background: color, boxShadow: `0 0 6px ${color}` }}
                  />
                )
              })}
            </div>
            <div className="flex gap-4 mt-3">
              {[['Weaponized', '#e8002d'], ['Active', '#f97316'], ['PoC', '#eab308']].map(([label, color]) => (
                <div key={label} className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />
                  <span className="text-falcon-muted text-xs">{label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Priority Queue Tab ── */}
      {activeTab === 'queue' && (
        <div className="space-y-4">
          {/* Formula */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <div className="flex items-center gap-3">
              <Shield className="w-4 h-4 text-falcon-red shrink-0" />
              <p className="text-falcon-muted text-sm">
                優先度スコア計算式:
                <span className="ml-2 font-mono text-white bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1">
                  (CVSS × 0.4) + (Exploit × 30) + (露出度 × 0.3)
                </span>
              </p>
            </div>
          </div>

          {/* Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['CVE', '優先度スコア', '影響資産数', 'エクスプロイト', 'パッチ経過日数', 'SLA期限', '担当者', 'ステータス', '操作'].map(h => (
                      <th key={h} className="text-left text-falcon-muted text-xs font-medium uppercase tracking-wider px-4 py-3 whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-falcon-border">
                  {m(MOCK_PRIORITY_QUEUE).map(item => {
                    const es = EXPLOIT_STATUS_CONFIG[item.exploit_status]
                    const scoreColor = item.priority_score >= 50 ? 'text-red-400' : item.priority_score >= 30 ? 'text-orange-400' : 'text-yellow-400'
                    return (
                      <tr key={item.cve_id} className="hover:bg-[#0a1628] transition-colors">
                        <td className="px-4 py-3">
                          <button
                            onClick={() => {
                              const cve = cves.find(c => c.id === item.cve_id)
                              if (cve) setSelectedCVE(cve)
                            }}
                            className="font-mono text-falcon-red text-sm font-bold hover:underline whitespace-nowrap"
                          >
                            {item.cve_id}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-2xl font-black ${scoreColor}`}>{item.priority_score}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-white font-semibold">{item.affected_assets}</span>
                        </td>
                        <td className="px-4 py-3"><Badge cls={es.cls}>{es.label}</Badge></td>
                        <td className="px-4 py-3">
                          {item.days_since_patch !== null
                            ? <span className={`text-sm font-medium ${item.days_since_patch > 30 ? 'text-red-400' : 'text-yellow-400'}`}>{item.days_since_patch}日</span>
                            : <span className="text-falcon-subtle text-sm">未適用</span>
                          }
                        </td>
                        <td className="px-4 py-3 text-falcon-muted text-sm whitespace-nowrap">{item.sla_deadline}</td>
                        <td className="px-4 py-3 text-white text-sm">{item.assignee}</td>
                        <td className="px-4 py-3">
                          <Badge cls={item.status === 'in_progress' ? 'bg-blue-900/40 border-blue-700 text-blue-300' : item.status === 'resolved' ? 'bg-green-900/40 border-green-700 text-green-300' : 'bg-gray-900/40 border-gray-700 text-gray-300'}>
                            {item.status === 'in_progress' ? '対応中' : item.status === 'resolved' ? '解決済み' : 'オープン'}
                          </Badge>
                        </td>
                        <td className="px-4 py-3">
                          <button className="px-3 py-1.5 bg-falcon-red/10 border border-falcon-red/30 text-falcon-red hover:bg-falcon-red/20 rounded-sm text-xs font-medium transition-colors whitespace-nowrap">
                            修復タスク作成
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* CVE Detail Modal */}
      {selectedCVE && <CVEDetailModal cve={selectedCVE} onClose={() => setSelectedCVE(null)} />}
    </div>
  )
}
