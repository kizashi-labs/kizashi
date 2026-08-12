'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Cpu, AlertTriangle, Shield, Activity, Search, Filter,
  X, CheckCircle, Clock, Zap, Eye, ChevronDown, ChevronUp,
  Wifi, Globe, BarChart3, AlertOctagon,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

type DeviceType = 'PLC' | 'HMI' | 'RTU' | 'SCADA' | 'Sensor' | 'Camera' | 'Printer' | 'Other_IoT'
type Protocol = 'Modbus' | 'DNP3' | 'BACnet' | 'OPC-UA' | 'MQTT' | 'HTTP' | 'Proprietary'
type NetworkZone = 'DMZ' | 'OT' | 'IoT' | 'Corporate'
type PatchStatus = 'current' | 'outdated' | 'unknown' | 'unsupported'
type AnomalyType = 'unusual_protocol' | 'command_injection' | 'unexpected_access' | 'config_change' | 'firmware_change' | 'communication_spike'
type AnomalySeverity = 'critical' | 'high' | 'medium' | 'low'
type AnomalyStatus = 'open' | 'investigating' | 'resolved' | 'false_positive'

interface IoTDevice {
  id: string
  device_name: string
  device_type: DeviceType
  ip_address: string
  vendor: string
  firmware_version: string
  protocol: Protocol
  network_zone: NetworkZone
  risk_score: number
  last_seen: string
  patch_status: PatchStatus
  open_ports: number[]
  known_vulns: string[]
  communicates_with: string[]
  hardening_steps: string[]
}

interface AnomalyAlert {
  id: string
  timestamp: string
  device_id: string
  device_name: string
  anomaly_type: AnomalyType
  severity: AnomalySeverity
  description: string
  status: AnomalyStatus
  protocol_context: string
  recommended_response: string
}

interface ModbusFC {
  code: number
  label: string
  count: number
  suspicious: boolean
}

interface ProtocolStats {
  name: Protocol
  percentage: number
  color: string
}

// ── Mock Data ──────────────────────────────────────────────────────────────────

const MOCK_DEVICES: IoTDevice[] = [
  {
    id: 'd-001', device_name: 'PLC-製造ライン1', device_type: 'PLC',
    ip_address: '10.10.1.11', vendor: 'Siemens', firmware_version: 'S7-1500 v2.9.4',
    protocol: 'Modbus', network_zone: 'OT', risk_score: 72, last_seen: '2026-03-18 14:32',
    patch_status: 'outdated',
    open_ports: [502, 102, 443],
    known_vulns: ['CVE-2023-44317 (CVSS 9.8): Remote code execution via Modbus', 'CVE-2022-38465 (CVSS 9.3): Key extraction vulnerability'],
    communicates_with: ['10.10.1.1 (HMI)', '10.10.1.20 (SCADA)', '10.10.2.5 (Engineer)'],
    hardening_steps: ['ファームウェアを最新版にアップデート', 'Modbusアクセスをホワイトリスト制限', '不要ポートを閉鎖', '定期バックアップを設定'],
  },
  {
    id: 'd-002', device_name: 'HMI-操作パネルA', device_type: 'HMI',
    ip_address: '10.10.1.1', vendor: 'Rockwell Automation', firmware_version: 'FactoryTalk v12.1',
    protocol: 'OPC-UA', network_zone: 'OT', risk_score: 55, last_seen: '2026-03-18 14:30',
    patch_status: 'outdated',
    open_ports: [4840, 80, 443],
    known_vulns: ['CVE-2024-0002 (CVSS 7.5): Unauthenticated OPC-UA access'],
    communicates_with: ['10.10.1.11 (PLC1)', '10.10.1.12 (PLC2)', '10.10.1.20 (SCADA)'],
    hardening_steps: ['OPC-UA認証を必須化', 'アクセス制御リストを設定', 'リモートアクセスを制限'],
  },
  {
    id: 'd-003', device_name: 'RTU-変電所1', device_type: 'RTU',
    ip_address: '10.10.1.30', vendor: 'ABB', firmware_version: 'RTU500 v12.7.1',
    protocol: 'DNP3', network_zone: 'OT', risk_score: 85, last_seen: '2026-03-18 13:55',
    patch_status: 'unsupported',
    open_ports: [20000, 502],
    known_vulns: ['EOL機器: ベンダーサポート終了', 'DNP3認証未実装'],
    communicates_with: ['10.10.1.20 (SCADA)', '10.10.1.35 (RTU2)'],
    hardening_steps: ['機器のリプレイスを計画', 'DNP3 SAv5認証を実装', 'ネットワーク分離を強化'],
  },
  {
    id: 'd-004', device_name: 'SCADA-中央制御', device_type: 'SCADA',
    ip_address: '10.10.1.20', vendor: 'Schneider Electric', firmware_version: 'Wonderware v2023.1',
    protocol: 'OPC-UA', network_zone: 'OT', risk_score: 68, last_seen: '2026-03-18 14:35',
    patch_status: 'current',
    open_ports: [4840, 443, 8080],
    known_vulns: [],
    communicates_with: ['10.10.1.11 (PLC1)', '10.10.1.30 (RTU1)', '192.168.10.5 (Corporate)'],
    hardening_steps: ['Corporateネットワークとの通信を監視', 'ログ収集設定を確認'],
  },
  {
    id: 'd-005', device_name: 'センサー-温度計測01', device_type: 'Sensor',
    ip_address: '10.20.1.50', vendor: 'Honeywell', firmware_version: 'v3.2.1',
    protocol: 'MQTT', network_zone: 'IoT', risk_score: 32, last_seen: '2026-03-18 14:33',
    patch_status: 'current',
    open_ports: [1883, 8883],
    known_vulns: [],
    communicates_with: ['10.20.1.1 (MQTT Broker)'],
    hardening_steps: ['TLS/MQTTを使用中 (良好)', '証明書有効期限を確認'],
  },
  {
    id: 'd-006', device_name: 'IPカメラ-工場入口', device_type: 'Camera',
    ip_address: '10.20.2.10', vendor: 'Hikvision', firmware_version: 'v5.6.7',
    protocol: 'HTTP', network_zone: 'IoT', risk_score: 88, last_seen: '2026-03-18 14:20',
    patch_status: 'outdated',
    open_ports: [80, 443, 554, 8000],
    known_vulns: ['CVE-2023-28808 (CVSS 9.8): Authentication bypass', 'デフォルト認証情報が変更されていない可能性'],
    communicates_with: ['10.20.2.1 (NVR)', '192.168.10.20 (Admin PC)'],
    hardening_steps: ['デフォルトパスワードを即座に変更', 'ファームウェアを更新', 'Corporateネットワークとの分離を確認', '80番ポートを閉鎖しHTTPSに統一'],
  },
  {
    id: 'd-007', device_name: 'BACnetコントローラー-空調1', device_type: 'Other_IoT',
    ip_address: '10.20.3.5', vendor: 'Johnson Controls', firmware_version: 'Metasys v11.0',
    protocol: 'BACnet', network_zone: 'IoT', risk_score: 45, last_seen: '2026-03-18 12:10',
    patch_status: 'current',
    open_ports: [47808],
    known_vulns: ['BACnet Who-Is/I-Am に応答: デバイス探索される可能性'],
    communicates_with: ['10.20.3.1 (BAS Controller)'],
    hardening_steps: ['BACnet通信を必要なセグメントのみに制限', 'Broadcastトラフィックを監視'],
  },
  {
    id: 'd-008', device_name: 'PLC-製造ライン2', device_type: 'PLC',
    ip_address: '10.10.1.12', vendor: 'Mitsubishi', firmware_version: 'MELSEC iQ-R v5.3',
    protocol: 'Modbus', network_zone: 'OT', risk_score: 40, last_seen: '2026-03-18 14:34',
    patch_status: 'current',
    open_ports: [502, 5007],
    known_vulns: [],
    communicates_with: ['10.10.1.1 (HMI)', '10.10.1.20 (SCADA)'],
    hardening_steps: ['定期的なファームウェア更新スケジュールを維持'],
  },
  {
    id: 'd-009', device_name: 'プリンター-管理棟1F', device_type: 'Printer',
    ip_address: '192.168.10.100', vendor: 'Canon', firmware_version: 'v3.10.0',
    protocol: 'HTTP', network_zone: 'Corporate', risk_score: 28, last_seen: '2026-03-18 14:00',
    patch_status: 'current',
    open_ports: [80, 443, 9100, 631],
    known_vulns: [],
    communicates_with: ['192.168.10.0/24 (Corporate)'],
    hardening_steps: ['プリントサーバー経由のアクセスに限定を検討'],
  },
  {
    id: 'd-010', device_name: 'センサー-圧力計測05', device_type: 'Sensor',
    ip_address: '10.20.1.55', vendor: 'Endress+Hauser', firmware_version: 'v2.1.0',
    protocol: 'MQTT', network_zone: 'IoT', risk_score: 20, last_seen: '2026-03-18 14:31',
    patch_status: 'current',
    open_ports: [8883],
    known_vulns: [],
    communicates_with: ['10.20.1.1 (MQTT Broker)'],
    hardening_steps: ['設定は適切です'],
  },
  {
    id: 'd-011', device_name: 'RTU-変電所2', device_type: 'RTU',
    ip_address: '10.10.1.35', vendor: 'GE Grid Solutions', firmware_version: 'D400 v8.5',
    protocol: 'DNP3', network_zone: 'OT', risk_score: 60, last_seen: '2026-03-18 11:45',
    patch_status: 'outdated',
    open_ports: [20000],
    known_vulns: ['CVE-2023-1701 (CVSS 6.5): DNP3 buffer overflow'],
    communicates_with: ['10.10.1.20 (SCADA)', '10.10.1.30 (RTU1)'],
    hardening_steps: ['ファームウェアを更新', 'DNP3認証を有効化'],
  },
  {
    id: 'd-012', device_name: 'IPカメラ-倉庫B', device_type: 'Camera',
    ip_address: '10.20.2.11', vendor: 'Axis', firmware_version: 'v11.9',
    protocol: 'HTTP', network_zone: 'IoT', risk_score: 35, last_seen: '2026-03-18 14:28',
    patch_status: 'current',
    open_ports: [80, 443, 554],
    known_vulns: [],
    communicates_with: ['10.20.2.1 (NVR)'],
    hardening_steps: ['設定は適切です'],
  },
  {
    id: 'd-013', device_name: 'HMI-操作パネルB', device_type: 'HMI',
    ip_address: '10.10.1.2', vendor: 'Siemens', firmware_version: 'WinCC v7.5 SP2',
    protocol: 'OPC-UA', network_zone: 'OT', risk_score: 48, last_seen: '2026-03-18 14:30',
    patch_status: 'current',
    open_ports: [4840, 443],
    known_vulns: [],
    communicates_with: ['10.10.1.12 (PLC2)', '10.10.1.20 (SCADA)'],
    hardening_steps: ['最新セキュリティパッチの確認'],
  },
  {
    id: 'd-014', device_name: 'センサー-流量計01', device_type: 'Sensor',
    ip_address: '10.20.1.60', vendor: 'Yokogawa', firmware_version: 'v4.1.2',
    protocol: 'MQTT', network_zone: 'IoT', risk_score: 22, last_seen: '2026-03-18 14:29',
    patch_status: 'current',
    open_ports: [8883],
    known_vulns: [],
    communicates_with: ['10.20.1.1 (MQTT Broker)'],
    hardening_steps: ['設定は適切です'],
  },
  {
    id: 'd-015', device_name: 'BACnet空調制御2', device_type: 'Other_IoT',
    ip_address: '10.20.3.6', vendor: 'Trane', firmware_version: 'Tracer SC+ v5.0',
    protocol: 'BACnet', network_zone: 'IoT', risk_score: 38, last_seen: '2026-03-18 09:15',
    patch_status: 'current',
    open_ports: [47808],
    known_vulns: [],
    communicates_with: ['10.20.3.1 (BAS Controller)'],
    hardening_steps: ['BACnetトラフィックを内部セグメントのみに制限'],
  },
  {
    id: 'd-016', device_name: 'SCADA-バックアップ', device_type: 'SCADA',
    ip_address: '10.10.1.21', vendor: 'Inductive Automation', firmware_version: 'Ignition v8.1.24',
    protocol: 'OPC-UA', network_zone: 'OT', risk_score: 42, last_seen: '2026-03-18 14:35',
    patch_status: 'current',
    open_ports: [8088, 8043, 4840],
    known_vulns: [],
    communicates_with: ['10.10.1.11 (PLC1)', '10.10.1.12 (PLC2)'],
    hardening_steps: ['Web GUIへのアクセスを制限', '外部ネットワークからのアクセスをブロック'],
  },
  {
    id: 'd-017', device_name: 'IPカメラ-外周03', device_type: 'Camera',
    ip_address: '10.20.2.13', vendor: 'Dahua', firmware_version: 'v2.820.00',
    protocol: 'HTTP', network_zone: 'IoT', risk_score: 75, last_seen: '2026-03-18 13:50',
    patch_status: 'outdated',
    known_vulns: ['CVE-2022-30563 (CVSS 9.8): Plaintext credential exposure', 'CVE-2021-33044 (CVSS 9.8): Authentication bypass'],
    open_ports: [80, 443, 37777, 554],
    communicates_with: ['10.20.2.1 (NVR)', '10.10.1.5 (Unexpected OT access)'],
    hardening_steps: ['重大脆弱性: 即座にネットワーク分離', 'ファームウェア更新または機器交換を検討'],
  },
  {
    id: 'd-018', device_name: 'センサー-振動計01', device_type: 'Sensor',
    ip_address: '10.20.1.70', vendor: 'SKF', firmware_version: 'v6.3.1',
    protocol: 'MQTT', network_zone: 'IoT', risk_score: 18, last_seen: '2026-03-18 14:32',
    patch_status: 'current',
    open_ports: [8883],
    known_vulns: [],
    communicates_with: ['10.20.1.1 (MQTT Broker)'],
    hardening_steps: ['設定は適切です'],
  },
  {
    id: 'd-019', device_name: 'プリンター-製造棟2F', device_type: 'Printer',
    ip_address: '10.10.5.200', vendor: 'HP', firmware_version: 'v5.5.0',
    protocol: 'HTTP', network_zone: 'OT',
    risk_score: 62, last_seen: '2026-03-18 10:20',
    patch_status: 'unknown',
    open_ports: [80, 443, 9100, 161],
    known_vulns: ['OTネットワーク内のプリンター: 不審な配置', 'SNMPコミュニティ文字列: publicのまま'],
    communicates_with: ['10.10.5.0/24 (OT subnet)', '192.168.10.50 (Admin)'],
    hardening_steps: ['OTネットワークからCorporateネットワークに移動', 'SNMPv3に移行またはSNMP無効化'],
  },
  {
    id: 'd-020', device_name: 'PLC-水処理', device_type: 'PLC',
    ip_address: '10.10.2.11', vendor: 'Allen-Bradley', firmware_version: 'ControlLogix v33.013',
    protocol: 'Modbus', network_zone: 'OT', risk_score: 78, last_seen: '2026-03-18 14:34',
    patch_status: 'outdated',
    open_ports: [502, 44818, 2222],
    known_vulns: ['CVE-2024-0057 (CVSS 8.8): Industrial protocol manipulation', 'ファームウェア脆弱性: 未パッチ'],
    communicates_with: ['10.10.2.1 (HMI)', '10.10.2.20 (SCADA)', '192.168.10.15 (Unexpected Corporate)'],
    hardening_steps: ['ファームウェアを即座に更新', 'Corporateネットワークとの通信を遮断', 'Modbusアクセス制御を実装'],
  },
]

const MOCK_ANOMALIES: AnomalyAlert[] = [
  {
    id: 'ano-001', timestamp: '2026-03-18 14:15:32', device_id: 'd-006', device_name: 'IPカメラ-工場入口',
    anomaly_type: 'unexpected_access', severity: 'critical', status: 'open',
    description: '既知のOT機器IPアドレスへの接続試行を検知。カメラがOTネットワークデバイスへのスキャンを実行中。',
    protocol_context: 'HTTP GET /cgi-bin/ 10.10.1.11:80 — OTデバイスへのポートスキャン',
    recommended_response: '【緊急】このカメラをネットワークから即座に分離してください。OTネットワークへの横展開の可能性があります。',
  },
  {
    id: 'ano-002', timestamp: '2026-03-18 13:48:11', device_id: 'd-001', device_name: 'PLC-製造ライン1',
    anomaly_type: 'command_injection', severity: 'high', status: 'investigating',
    description: 'Modbus Function Code 16 (Write Multiple Registers) が通常外の送信元IPから送信された。設定変更の可能性。',
    protocol_context: 'Modbus FC16 from 10.10.5.200 (Printer) — 通常のHMI/SCADAからではない',
    recommended_response: 'FC16送信元を確認。プリンター(10.10.5.200)から送信されているため即座に調査。ベースラインに存在しない通信パターン。',
  },
  {
    id: 'ano-003', timestamp: '2026-03-18 13:20:05', device_id: 'd-020', device_name: 'PLC-水処理',
    anomaly_type: 'unexpected_access', severity: 'high', status: 'open',
    description: 'CorporateネットワークIPからPLCへの直接Modbus通信を検知。このPLCはOT-Corporate間通信が許可されていない。',
    protocol_context: 'Modbus TCP from 192.168.10.15 to 10.10.2.11:502',
    recommended_response: '通信をブロックし、192.168.10.15のコンピューターを調査。OT/Corporateの境界ファイアウォールルールを見直す。',
  },
  {
    id: 'ano-004', timestamp: '2026-03-18 12:55:44', device_id: 'd-003', device_name: 'RTU-変電所1',
    anomaly_type: 'firmware_change', severity: 'critical', status: 'open',
    description: 'RTUのファームウェアバージョン変化を検知。前回確認時からハッシュ値が変更されている。',
    protocol_context: 'DNP3 Device Attributes response: firmware version changed from v12.7.1 to v12.7.1-mod',
    recommended_response: '【緊急】変電所RTUのファームウェア変更は重大インシデントの可能性。物理アクセスログを確認し、保守作業との照合を行ってください。',
  },
  {
    id: 'ano-005', timestamp: '2026-03-18 11:30:22', device_id: 'd-007', device_name: 'BACnetコントローラー-空調1',
    anomaly_type: 'unusual_protocol', severity: 'medium', status: 'resolved',
    description: 'BACnet Who-Is ブロードキャストの頻度が通常の20倍に増加。デバイス探索ストームの可能性。',
    protocol_context: 'BACnet/IP Who-Is broadcast: 847 packets in 5 minutes (normal: 40/5min)',
    recommended_response: 'BACnetブロードキャストをセグメント内に制限。他のBACnetデバイスへの影響を確認。',
  },
  {
    id: 'ano-006', timestamp: '2026-03-18 10:12:18', device_id: 'd-017', device_name: 'IPカメラ-外周03',
    anomaly_type: 'communication_spike', severity: 'high', status: 'investigating',
    description: '深夜時間帯(03:00-04:00)に異常な送信トラフィックスパイクを検知。データ漏洩の疑い。',
    protocol_context: 'HTTP POST to 103.45.67.89 (外部IP) — 2.3GB転送 @03:15',
    recommended_response: '外部IPへの通信を遮断。ファイアウォールで103.45.67.89をブロック。機器の完全な調査が必要。',
  },
  {
    id: 'ano-007', timestamp: '2026-03-18 09:45:33', device_id: 'd-002', device_name: 'HMI-操作パネルA',
    anomaly_type: 'config_change', severity: 'medium', status: 'resolved',
    description: 'OPC-UAサーバー設定の変更を検知。認証設定が "None" に変更されていた。',
    protocol_context: 'OPC-UA SecurityMode: None, SecurityPolicy: None (was: SignAndEncrypt)',
    recommended_response: '設定を即座に元に戻す。変更を行ったユーザーを特定し、変更の理由を確認。',
  },
  {
    id: 'ano-008', timestamp: '2026-03-18 08:30:10', device_id: 'd-001', device_name: 'PLC-製造ライン1',
    anomaly_type: 'unusual_protocol', severity: 'low', status: 'false_positive',
    description: 'Modbusポートへの予期しないSYNパケットを検知。脆弱性スキャンの可能性。',
    protocol_context: 'TCP SYN from 10.10.5.100 to 10.10.1.11:502 — 承認済みスキャンと一致',
    recommended_response: '定期セキュリティスキャンによる誤検知と確認。ホワイトリストに追加済み。',
  },
  {
    id: 'ano-009', timestamp: '2026-03-17 22:15:55', device_id: 'd-011', device_name: 'RTU-変電所2',
    anomaly_type: 'unexpected_access', severity: 'medium', status: 'open',
    description: 'メンテナンス時間外にRTUへのDNP3接続を検知。',
    protocol_context: 'DNP3 from 10.10.1.50 (unknown IP) at 22:15 — outside maintenance window',
    recommended_response: '10.10.1.50のIPアドレスを特定。夜間アクセスの正当性を確認。',
  },
  {
    id: 'ano-010', timestamp: '2026-03-17 18:44:20', device_id: 'd-004', device_name: 'SCADA-中央制御',
    anomaly_type: 'unexpected_access', severity: 'high', status: 'investigating',
    description: 'SCADAからCorporateネットワークへの大量データ転送を検知。通常は読み取り専用の通信。',
    protocol_context: 'OPC-UA Write operations to 192.168.10.5 — 156MB transferred, unusual write activity',
    recommended_response: 'SCADA/Corporate間の書き込み通信を監視。192.168.10.5のホストを調査し、不正アクセスがないか確認。',
  },
]

const PROTOCOL_STATS: ProtocolStats[] = [
  { name: 'Modbus', percentage: 34, color: '#e8002d' },
  { name: 'OPC-UA', percentage: 22, color: '#1a6bff' },
  { name: 'MQTT', percentage: 18, color: '#00c853' },
  { name: 'DNP3', percentage: 12, color: '#ffc107' },
  { name: 'BACnet', percentage: 8, color: '#9c27b0' },
  { name: 'HTTP', percentage: 4, color: '#ff9800' },
  { name: 'Proprietary', percentage: 2, color: '#607d8b' },
]

const MODBUS_FCS: ModbusFC[] = [
  { code: 1, label: 'FC01 Read Coils', count: 12450, suspicious: false },
  { code: 2, label: 'FC02 Read Discrete Inputs', count: 8820, suspicious: false },
  { code: 3, label: 'FC03 Read Holding Registers', count: 34200, suspicious: false },
  { code: 4, label: 'FC04 Read Input Registers', count: 22100, suspicious: false },
  { code: 5, label: 'FC05 Write Single Coil', count: 1250, suspicious: false },
  { code: 6, label: 'FC06 Write Single Register', count: 880, suspicious: false },
  { code: 15, label: 'FC15 Write Multiple Coils', count: 124, suspicious: false },
  { code: 16, label: 'FC16 Write Multiple Registers', count: 47, suspicious: true },
  { code: 43, label: 'FC43 Read Device ID', count: 3, suspicious: true },
  { code: 8, label: 'FC08 Diagnostic', count: 2, suspicious: true },
]

// ── Helpers ────────────────────────────────────────────────────────────────────

const DEVICE_TYPE_COLORS: Record<DeviceType, string> = {
  PLC: 'bg-red-500/20 text-red-300 border-red-500/30',
  HMI: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  RTU: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  SCADA: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  Sensor: 'bg-green-500/20 text-green-300 border-green-500/30',
  Camera: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  Printer: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
  Other_IoT: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
}

const PROTOCOL_COLORS: Record<Protocol, string> = {
  Modbus: 'bg-red-500/20 text-red-300 border-red-500/30',
  DNP3: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  BACnet: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  'OPC-UA': 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  MQTT: 'bg-green-500/20 text-green-300 border-green-500/30',
  HTTP: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  Proprietary: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
}

const ZONE_COLORS: Record<NetworkZone, string> = {
  OT: 'bg-red-500/20 text-red-300 border-red-500/30',
  IoT: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  DMZ: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  Corporate: 'bg-green-500/20 text-green-300 border-green-500/30',
}

const PATCH_COLORS: Record<PatchStatus, string> = {
  current: 'bg-green-500/20 text-green-300 border-green-500/30',
  outdated: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  unknown: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
  unsupported: 'bg-red-500/20 text-red-300 border-red-500/30',
}

const SEVERITY_COLORS: Record<AnomalySeverity, string> = {
  critical: 'bg-red-500/20 text-red-300 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  low: 'bg-green-500/20 text-green-300 border-green-500/30',
}

const ANOMALY_TYPE_LABELS: Record<AnomalyType, string> = {
  unusual_protocol: '異常プロトコル',
  command_injection: 'コマンド注入',
  unexpected_access: '不審アクセス',
  config_change: '設定変更',
  firmware_change: 'ファームウェア変更',
  communication_spike: '通信スパイク',
}

const ANOMALY_STATUS_CONFIG: Record<AnomalyStatus, { label: string; color: string }> = {
  open: { label: 'オープン', color: 'text-red-400' },
  investigating: { label: '調査中', color: 'text-yellow-400' },
  resolved: { label: '解決済', color: 'text-green-400' },
  false_positive: { label: '誤検知', color: 'text-[#7d92b0]' },
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? '#e8002d' : score >= 50 ? '#ffc107' : '#00c853'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs font-medium" style={{ color }}>{score}</span>
    </div>
  )
}

function DeviceDetailModal({ device, onClose }: { device: IoTDevice; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto p-6 shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-white font-semibold text-lg">{device.device_name}</h2>
            <p className="text-[#7d92b0] text-sm">{device.ip_address} — {device.vendor}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0]"><X className="w-5 h-5" /></button>
        </div>

        <div className="space-y-4">
          {/* Info grid */}
          <div className="grid grid-cols-2 gap-3 text-sm">
            {[
              { label: 'デバイスタイプ', value: device.device_type, badge: DEVICE_TYPE_COLORS[device.device_type] },
              { label: 'プロトコル', value: device.protocol, badge: PROTOCOL_COLORS[device.protocol] },
              { label: 'ネットワークゾーン', value: device.network_zone, badge: ZONE_COLORS[device.network_zone] },
              { label: 'パッチ状態', value: device.patch_status, badge: PATCH_COLORS[device.patch_status] },
            ].map(r => (
              <div key={r.label} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
                <p className="text-[#7d92b0] text-xs mb-1">{r.label}</p>
                <span className={`px-2 py-0.5 rounded text-xs border ${r.badge}`}>{r.value}</span>
              </div>
            ))}
          </div>

          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 text-sm">
            <p className="text-[#7d92b0] text-xs mb-1">ファームウェア</p>
            <p className="text-white font-mono text-xs">{device.firmware_version}</p>
          </div>

          {/* Open ports */}
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
            <p className="text-[#7d92b0] text-xs mb-2">オープンポート</p>
            <div className="flex flex-wrap gap-2">
              {device.open_ports.map(p => (
                <span key={p} className="font-mono text-xs px-2 py-1 bg-[#1e2d42] text-[#7d92b0] rounded">{p}</span>
              ))}
            </div>
          </div>

          {/* Known vulns */}
          {device.known_vulns.length > 0 && (
            <div className="bg-[#070d19] border border-red-500/20 rounded-lg p-3">
              <p className="text-red-300 text-xs mb-2 flex items-center gap-1"><AlertTriangle className="w-3 h-3" />既知の脆弱性</p>
              <ul className="space-y-1">
                {device.known_vulns.map((v, i) => <li key={i} className="text-red-300/80 text-xs">• {v}</li>)}
              </ul>
            </div>
          )}

          {/* Communication patterns */}
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
            <p className="text-[#7d92b0] text-xs mb-2">通信先</p>
            <div className="space-y-1">
              {device.communicates_with.map((c, i) => (
                <div key={i} className="text-xs text-white font-mono bg-[#0d1220] px-2 py-1 rounded">{c}</div>
              ))}
            </div>
          </div>

          {/* Hardening */}
          <div className="bg-[#070d19] border border-green-500/20 rounded-lg p-3">
            <p className="text-green-300 text-xs mb-2 flex items-center gap-1"><Shield className="w-3 h-3" />推奨ハードニング手順</p>
            <ul className="space-y-1">
              {device.hardening_steps.map((s, i) => <li key={i} className="text-green-300/80 text-xs">• {s}</li>)}
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}

function AnomalyDetailModal({ alert, onClose }: { alert: AnomalyAlert; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-xl p-6 shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-white font-semibold">異常アラート詳細</h2>
          </div>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-[#1e2d42] text-[#7d92b0]"><X className="w-5 h-5" /></button>
        </div>

        <div className="space-y-4 text-sm">
          <div className="flex flex-wrap gap-2">
            <span className={`px-2 py-0.5 rounded text-xs border ${SEVERITY_COLORS[alert.severity]}`}>{alert.severity.toUpperCase()}</span>
            <span className="px-2 py-0.5 rounded text-xs border bg-blue-500/20 text-blue-300 border-blue-500/30">{ANOMALY_TYPE_LABELS[alert.anomaly_type]}</span>
            <span className={`text-xs font-medium ${ANOMALY_STATUS_CONFIG[alert.status].color}`}>{ANOMALY_STATUS_CONFIG[alert.status].label}</span>
          </div>

          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
            <p className="text-[#7d92b0] text-xs mb-1">影響デバイス</p>
            <p className="text-white font-medium">{alert.device_name}</p>
            <p className="text-[#7d92b0] text-xs mt-0.5">{alert.timestamp}</p>
          </div>

          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
            <p className="text-[#7d92b0] text-xs mb-1">説明</p>
            <p className="text-white text-xs leading-relaxed">{alert.description}</p>
          </div>

          <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
            <p className="text-[#7d92b0] text-xs mb-1">プロトコルコンテキスト</p>
            <p className="text-cyan-300 text-xs font-mono leading-relaxed">{alert.protocol_context}</p>
          </div>

          <div className={`border rounded-lg p-3 ${alert.severity === 'critical' ? 'border-red-500/30 bg-red-500/5' : 'border-yellow-500/20 bg-yellow-500/5'}`}>
            <p className={`text-xs mb-1 font-medium ${alert.severity === 'critical' ? 'text-red-300' : 'text-yellow-300'}`}>推奨対応</p>
            <p className="text-white text-xs leading-relaxed">{alert.recommended_response}</p>
            {(alert.device_name.includes('PLC') || alert.device_name.includes('RTU') || alert.device_name.includes('SCADA')) && (
              <p className="text-yellow-300/70 text-xs mt-2 italic">注: OT機器の隔離は運用への重大な影響を与える可能性があります。クリティカルな場合を除き、まずアラート監視を継続してください。</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── OT Protocol sub-tabs ───────────────────────────────────────────────────────

function ModbusAnalysis() {
  const maxCount = Math.max(...MODBUS_FCS.map(f => f.count))
  return (
    <div className="space-y-4">
      <h3 className="text-white font-medium">Modbus ファンクションコード分布</h3>
      <div className="space-y-2">
        {MODBUS_FCS.map(fc => (
          <div key={fc.code} className={`flex items-center gap-3 px-4 py-2.5 rounded-lg border ${fc.suspicious ? 'border-red-500/30 bg-red-500/5' : 'border-[#1e2d42] bg-[#070d19]'}`}>
            <div className="w-40 text-xs text-[#7d92b0]">{fc.label}</div>
            <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all"
                style={{ width: `${(fc.count / maxCount) * 100}%`, backgroundColor: fc.suspicious ? '#e8002d' : '#1a6bff' }}
              />
            </div>
            <div className="w-16 text-right text-xs text-white">{(fc.count ?? 0).toLocaleString()}</div>
            {fc.suspicious && <span className="text-red-400 text-xs">⚠ 要注意</span>}
          </div>
        ))}
      </div>
    </div>
  )
}

function DNP3Analysis() {
  return (
    <div className="space-y-4">
      <h3 className="text-white font-medium">DNP3 トラフィック分析</h3>
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-[#070d19] border border-yellow-500/20 rounded-lg p-4">
          <p className="text-yellow-300 text-sm font-medium mb-2">Unsolicited Response</p>
          <p className="text-3xl font-bold text-white">23</p>
          <p className="text-[#7d92b0] text-xs mt-1">過去24時間 (通常: &lt;5)</p>
          <p className="text-yellow-300 text-xs mt-2">RTU-変電所1からの未要求レスポンス増加</p>
        </div>
        <div className="bg-[#070d19] border border-red-500/20 rounded-lg p-4">
          <p className="text-red-300 text-sm font-medium mb-2">Broadcast Traffic</p>
          <p className="text-3xl font-bold text-white">7</p>
          <p className="text-[#7d92b0] text-xs mt-1">過去24時間 (通常: 0)</p>
          <p className="text-red-300 text-xs mt-2">DNP3ブロードキャストは設定ミスまたは攻撃の可能性</p>
        </div>
      </div>
      <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
        <p className="text-white font-medium mb-3">DNP3認証状態</p>
        <div className="space-y-2">
          {[
            { device: 'RTU-変電所1', auth: '未実装', color: 'text-red-400' },
            { device: 'RTU-変電所2', auth: 'SAv5 (設定中)', color: 'text-yellow-400' },
          ].map(r => (
            <div key={r.device} className="flex justify-between text-sm">
              <span className="text-[#7d92b0]">{r.device}</span>
              <span className={r.color}>{r.auth}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function BACnetAnalysis() {
  return (
    <div className="space-y-4">
      <h3 className="text-white font-medium">BACnet トラフィック分析</h3>
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 text-center">
          <p className="text-[#7d92b0] text-xs mb-1">Who-Is ブロードキャスト</p>
          <p className="text-2xl font-bold text-white">1,247</p>
          <p className="text-[#3d5068] text-xs">過去1時間</p>
        </div>
        <div className="bg-[#070d19] border border-yellow-500/20 rounded-lg p-4 text-center">
          <p className="text-yellow-300 text-xs mb-1">Who-Is Storm 検知</p>
          <p className="text-2xl font-bold text-yellow-400">1件</p>
          <p className="text-[#3d5068] text-xs">BACnet空調制御-1</p>
        </div>
        <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 text-center">
          <p className="text-[#7d92b0] text-xs mb-1">I-Am 応答デバイス数</p>
          <p className="text-2xl font-bold text-white">3</p>
          <p className="text-[#3d5068] text-xs">検出済みデバイス</p>
        </div>
      </div>
      <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4">
        <p className="text-white font-medium mb-3">BACnetデバイス探索ログ</p>
        <div className="space-y-1 font-mono text-xs">
          {[
            { time: '14:15:32', msg: 'BACnet Who-Is broadcast from 10.20.3.5 (BACnetコントローラー-空調1)', warn: true },
            { time: '14:15:32', msg: 'BACnet I-Am response: 10.20.3.5 (Device ID: 1001)', warn: false },
            { time: '14:15:33', msg: 'BACnet I-Am response: 10.20.3.6 (Device ID: 1002)', warn: false },
            { time: '14:15:33', msg: 'BACnet I-Am response: 10.20.3.1 (Device ID: 9001 — BAS Controller)', warn: false },
          ].map((l, i) => (
            <div key={i} className={`flex gap-3 ${l.warn ? 'text-yellow-300' : 'text-[#7d92b0]'}`}>
              <span className="text-[#3d5068]">{l.time}</span>
              <span>{l.msg}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function IoTOTSecurityPage() {
  const [tab, setTab] = useState<'devices' | 'anomalies' | 'protocols'>('devices')
  const [selectedDevice, setSelectedDevice] = useState<IoTDevice | null>(null)
  const [selectedAnomaly, setSelectedAnomaly] = useState<AnomalyAlert | null>(null)
  const [filterType, setFilterType] = useState<DeviceType | 'all'>('all')
  const [filterZone, setFilterZone] = useState<NetworkZone | 'all'>('all')
  const [filterPatch, setFilterPatch] = useState<PatchStatus | 'all'>('all')
  const [filterProtocol, setFilterProtocol] = useState<Protocol | 'all'>('all')
  const [searchQ, setSearchQ] = useState('')
  const [showScanWarning, setShowScanWarning] = useState(false)
  const [scanRunning, setScanRunning] = useState(false)
  const [protoSubTab, setProtoSubTab] = useState<'modbus' | 'dnp3' | 'bacnet'>('modbus')

  const { data: remoteDevices } = useQuery<IoTDevice[]>({
    queryKey: ['iot-ot-devices'],
    queryFn: () => apiFetch('/api/v1/iot-ot/devices'),
    retry: false, staleTime: 60_000,
  })
  const { data: remoteAnomalies } = useQuery<AnomalyAlert[]>({
    queryKey: ['iot-ot-anomalies'],
    queryFn: () => apiFetch('/api/v1/iot-ot/anomalies'),
    retry: false, staleTime: 30_000,
  })

  const devices = remoteDevices ?? []
  const anomalies = remoteAnomalies ?? []

  const stats = useMemo(() => ({
    iot: devices.filter(d => d.network_zone === 'IoT').length,
    ot: devices.filter(d => d.network_zone === 'OT').length,
    unpatched: devices.filter(d => d.patch_status === 'outdated' || d.patch_status === 'unsupported').length,
    anomalies_today: anomalies.filter(a => a.timestamp.startsWith('2026-03-18') && a.status !== 'false_positive').length,
  }), [devices, anomalies])

  const filteredDevices = useMemo(() => devices.filter(d => {
    if (filterType !== 'all' && d.device_type !== filterType) return false
    if (filterZone !== 'all' && d.network_zone !== filterZone) return false
    if (filterPatch !== 'all' && d.patch_status !== filterPatch) return false
    if (filterProtocol !== 'all' && d.protocol !== filterProtocol) return false
    if (searchQ && !d.device_name.toLowerCase().includes(searchQ.toLowerCase()) && !d.ip_address.includes(searchQ)) return false
    return true
  }), [devices, filterType, filterZone, filterPatch, filterProtocol, searchQ])

  // Cross-zone communication: IoT/OT -> Corporate
  const crossZone = useMemo(() => devices.filter(d =>
    (d.network_zone === 'OT' || d.network_zone === 'IoT') &&
    d.communicates_with.some(c => c.includes('192.168.') || c.includes('Corporate'))
  ), [devices])

  const handleScan = () => {
    setShowScanWarning(false)
    setScanRunning(true)
    setTimeout(() => setScanRunning(false), 3000)
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0]">
      {/* Header */}
      <div className="border-b border-[#1e2d42] bg-[#0d1220] px-6 py-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-[#e8002d]/10 border border-[#e8002d]/20 rounded-lg">
              <Cpu className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-white font-semibold text-xl">IoT/OTセキュリティ監視</h1>
              <p className="text-[#7d92b0] text-sm">産業制御システムとIoTデバイスのセキュリティ監視</p>
            </div>
          </div>
          {tab === 'devices' && (
            <button
              onClick={() => setShowScanWarning(true)}
              disabled={scanRunning}
              className="flex items-center gap-2 px-4 py-2 border border-[#1e2d42] hover:border-yellow-500/40 text-[#7d92b0] hover:text-yellow-300 text-sm rounded-lg transition-colors disabled:opacity-50"
            >
              {scanRunning ? <Activity className="w-4 h-4 animate-pulse" /> : <Search className="w-4 h-4" />}
              {scanRunning ? 'スキャン中...' : 'デバイス検出スキャン'}
            </button>
          )}
        </div>

        {/* Warning banner */}
        <div className="flex items-start gap-2 px-4 py-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
          <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
          <p className="text-yellow-300 text-sm">
            <strong>注意:</strong> OT環境への変更は慎重に行ってください。スキャンにより機器が応答停止する可能性があります。変更前に必ず運用チームと調整してください。
          </p>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-4 gap-4 mt-4">
          {[
            { label: 'IoTデバイス', value: stats.iot, color: 'text-blue-400', icon: Wifi },
            { label: 'OTデバイス', value: stats.ot, color: 'text-red-400', icon: Cpu },
            { label: '未パッチデバイス', value: stats.unpatched, color: 'text-yellow-400', icon: AlertTriangle },
            { label: '本日の異常検知', value: stats.anomalies_today, color: 'text-[#e8002d]', icon: AlertOctagon },
          ].map(s => (
            <div key={s.label} className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-4 py-3">
              <div className="flex items-center gap-2 mb-1">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <p className="text-[#7d92b0] text-xs">{s.label}</p>
              </div>
              <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="px-6 pt-4 border-b border-[#1e2d42]">
        <div className="flex gap-1">
          {([['devices', 'デバイス一覧'], ['anomalies', '異常検知'], ['protocols', 'OTプロトコル分析']] as const).map(([id, label]) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`px-4 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors ${tab === id ? 'border-[#e8002d] text-white' : 'border-transparent text-[#7d92b0] hover:text-white'}`}
            >
              {label}
              {id === 'anomalies' && stats.anomalies_today > 0 && (
                <span className="ml-1.5 text-[10px] bg-[#e8002d] text-white px-1.5 py-0.5 rounded-full">{stats.anomalies_today}</span>
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="p-6 space-y-4">
        {/* ── デバイス一覧 ── */}
        {tab === 'devices' && (
          <>
            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[180px]">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
                <input
                  value={searchQ} onChange={e => setSearchQ(e.target.value)}
                  placeholder="デバイス名・IPで検索..."
                  className="w-full pl-9 pr-4 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-sm text-white placeholder-[#3d5068] focus:outline-none focus:border-[#e8002d]/50"
                />
              </div>
              {[
                { value: filterType, setter: (v: string) => setFilterType(v as DeviceType | 'all'), options: ['all', 'PLC', 'HMI', 'RTU', 'SCADA', 'Sensor', 'Camera', 'Printer', 'Other_IoT'], label: 'タイプ' },
                { value: filterZone, setter: (v: string) => setFilterZone(v as NetworkZone | 'all'), options: ['all', 'OT', 'IoT', 'DMZ', 'Corporate'], label: 'ゾーン' },
                { value: filterPatch, setter: (v: string) => setFilterPatch(v as PatchStatus | 'all'), options: ['all', 'current', 'outdated', 'unknown', 'unsupported'], label: 'パッチ' },
                { value: filterProtocol, setter: (v: string) => setFilterProtocol(v as Protocol | 'all'), options: ['all', 'Modbus', 'DNP3', 'BACnet', 'OPC-UA', 'MQTT', 'HTTP', 'Proprietary'], label: 'プロトコル' },
              ].map(f => (
                <select
                  key={f.label}
                  value={f.value}
                  onChange={e => f.setter(e.target.value)}
                  className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#7d92b0] focus:outline-none"
                >
                  <option value="all">全{f.label}</option>
                  {f.options.slice(1).map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              ))}
              <span className="text-[#3d5068] text-xs">{filteredDevices.length}件</span>
            </div>

            {/* Device table */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      {['デバイス名', 'タイプ', 'IPアドレス', 'ベンダー', 'プロトコル', 'ゾーン', 'リスク', '最終確認', 'パッチ', '操作'].map(h => (
                        <th key={h} className="px-3 py-3 text-left text-xs font-medium text-[#7d92b0] uppercase tracking-wider whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]/50">
                    {filteredDevices.map(d => (
                      <tr key={d.id} className={`hover:bg-[#070d19]/50 transition-colors ${d.known_vulns.length > 0 ? 'border-l-2 border-l-red-500/40' : ''}`}>
                        <td className="px-3 py-3">
                          <p className="text-white font-medium text-xs">{d.device_name}</p>
                          {d.known_vulns.length > 0 && <p className="text-red-400 text-[10px]">{d.known_vulns.length}件の脆弱性</p>}
                        </td>
                        <td className="px-3 py-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] border ${DEVICE_TYPE_COLORS[d.device_type]}`}>{d.device_type}</span>
                        </td>
                        <td className="px-3 py-3">
                          <code className="text-cyan-300 text-xs font-mono">{d.ip_address}</code>
                        </td>
                        <td className="px-3 py-3 text-[#7d92b0] text-xs">{d.vendor}</td>
                        <td className="px-3 py-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] border ${PROTOCOL_COLORS[d.protocol]}`}>{d.protocol}</span>
                        </td>
                        <td className="px-3 py-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] border ${ZONE_COLORS[d.network_zone]}`}>{d.network_zone}</span>
                        </td>
                        <td className="px-3 py-3">
                          <RiskBar score={d.risk_score} />
                        </td>
                        <td className="px-3 py-3 text-[#7d92b0] text-xs whitespace-nowrap">{d.last_seen}</td>
                        <td className="px-3 py-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] border ${PATCH_COLORS[d.patch_status]}`}>{d.patch_status}</span>
                        </td>
                        <td className="px-3 py-3">
                          <button
                            onClick={() => setSelectedDevice(d)}
                            className="px-2 py-1 bg-[#1e2d42] hover:bg-[#253a56] text-[#7d92b0] hover:text-white text-xs rounded transition-colors"
                          >
                            詳細
                          </button>
                        </td>
                      </tr>
                    ))}
                    {filteredDevices.length === 0 && (
                      <tr><td colSpan={10} className="px-4 py-12 text-center text-[#3d5068]">条件に一致するデバイスが見つかりません</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {/* ── 異常検知 ── */}
        {tab === 'anomalies' && (
          <>
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['タイムスタンプ', 'デバイス名', '異常タイプ', '深刻度', '説明', 'ステータス', '操作'].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#7d92b0]">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]/50">
                  {anomalies.map(a => (
                    <tr key={a.id} className={`hover:bg-[#070d19]/50 transition-colors ${a.severity === 'critical' ? 'border-l-2 border-l-red-500' : ''}`}>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs font-mono whitespace-nowrap">{a.timestamp}</td>
                      <td className="px-4 py-3 text-white text-xs font-medium">{a.device_name}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 bg-blue-500/10 border border-blue-500/20 text-blue-300 text-xs rounded">
                          {ANOMALY_TYPE_LABELS[a.anomaly_type]}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs border ${SEVERITY_COLORS[a.severity]}`}>{a.severity.toUpperCase()}</span>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs max-w-xs truncate" title={a.description}>{a.description}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-medium ${ANOMALY_STATUS_CONFIG[a.status].color}`}>{ANOMALY_STATUS_CONFIG[a.status].label}</span>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => setSelectedAnomaly(a)}
                          className="px-2.5 py-1 bg-[#1e2d42] hover:bg-[#253a56] text-[#7d92b0] hover:text-white text-xs rounded transition-colors"
                        >
                          詳細
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* ── OTプロトコル分析 ── */}
        {tab === 'protocols' && (
          <div className="space-y-6">
            {/* Protocol distribution */}
            <div className="grid grid-cols-2 gap-6">
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <h3 className="text-white font-medium mb-4">プロトコル分布</h3>
                <div className="space-y-3">
                  {PROTOCOL_STATS.map(p => (
                    <div key={p.name} className="flex items-center gap-3">
                      <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: p.color }} />
                      <span className="text-[#7d92b0] text-sm w-20">{p.name}</span>
                      <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-all" style={{ width: `${p.percentage}%`, backgroundColor: p.color }} />
                      </div>
                      <span className="text-white text-xs w-8 text-right">{p.percentage}%</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Cross-zone communications */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <h3 className="text-white font-medium mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400" />
                  クロスゾーン通信 (要監視)
                </h3>
                <div className="space-y-2">
                  {crossZone.map(d => (
                    <div key={d.id} className="bg-[#070d19] border border-yellow-500/20 rounded-lg px-3 py-2.5">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-white text-xs font-medium">{d.device_name}</span>
                        <span className={`text-xs px-1.5 py-0.5 rounded border ${ZONE_COLORS[d.network_zone]}`}>{d.network_zone}</span>
                      </div>
                      <div className="space-y-0.5">
                        {d.communicates_with.filter(c => c.includes('192.168.') || c.includes('Corporate')).map((c, i) => (
                          <p key={i} className="text-yellow-300 text-[10px] font-mono">{c}</p>
                        ))}
                      </div>
                    </div>
                  ))}
                  {crossZone.length === 0 && <p className="text-[#3d5068] text-sm">クロスゾーン通信は検知されていません</p>}
                </div>
              </div>
            </div>

            {/* Protocol-specific analysis */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <div className="flex gap-1 mb-5 border-b border-[#1e2d42] pb-3">
                {([['modbus', 'Modbus'], ['dnp3', 'DNP3'], ['bacnet', 'BACnet']] as const).map(([id, label]) => (
                  <button
                    key={id}
                    onClick={() => setProtoSubTab(id)}
                    className={`px-4 py-1.5 text-sm rounded-lg transition-colors ${protoSubTab === id ? 'bg-[#e8002d]/20 border border-[#e8002d]/30 text-[#e8002d]' : 'text-[#7d92b0] hover:text-white hover:bg-[#1e2d42]'}`}
                  >
                    {label}
                  </button>
                ))}
              </div>
              {protoSubTab === 'modbus' && <ModbusAnalysis />}
              {protoSubTab === 'dnp3' && <DNP3Analysis />}
              {protoSubTab === 'bacnet' && <BACnetAnalysis />}
            </div>

            {/* Dangerous commands */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <h3 className="text-white font-medium mb-4 flex items-center gap-2"><Zap className="w-4 h-4 text-red-400" />危険コマンド検知</h3>
              <div className="space-y-3">
                {[
                  { time: '2026-03-18 13:48', device: 'PLC-製造ライン1', cmd: 'Modbus FC16 Write Multiple Registers', src: '10.10.5.200 (Printer)', severity: 'high', detail: 'プリンターからPLCへの書き込みコマンドは正常ではありません。横断的攻撃の可能性。' },
                  { time: '2026-03-18 09:22', device: 'PLC-水処理', cmd: 'Modbus FC43 Read Device Identification', src: '192.168.10.15 (Corporate)', severity: 'high', detail: 'CorporateネットワークからOTデバイスへの探索コマンド。偵察行動の疑い。' },
                  { time: '2026-03-17 22:10', device: 'RTU-変電所1', cmd: 'DNP3 Direct Operate Command (Function Code 3)', src: '10.10.1.50 (Unknown)', severity: 'critical', detail: '不明なIPから変電所への直接操作コマンド。物理的影響のある操作が試みられた可能性。' },
                ].map((c, i) => (
                  <div key={i} className={`border rounded-lg px-4 py-3 ${c.severity === 'critical' ? 'border-red-500/40 bg-red-500/5' : 'border-orange-500/30 bg-orange-500/5'}`}>
                    <div className="flex items-start justify-between gap-3 mb-2">
                      <div>
                        <span className={`text-xs font-bold ${c.severity === 'critical' ? 'text-red-400' : 'text-orange-400'}`}>[{c.severity.toUpperCase()}]</span>
                        <span className="text-white text-sm font-medium ml-2">{c.cmd}</span>
                      </div>
                      <span className="text-[#3d5068] text-xs whitespace-nowrap">{c.time}</span>
                    </div>
                    <div className="text-xs space-y-0.5">
                      <p><span className="text-[#7d92b0]">対象:</span> <span className="text-white">{c.device}</span></p>
                      <p><span className="text-[#7d92b0]">送信元:</span> <span className="font-mono text-cyan-300">{c.src}</span></p>
                      <p className={`mt-1 ${c.severity === 'critical' ? 'text-red-300' : 'text-orange-300'}`}>{c.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Modals */}
      {selectedDevice && <DeviceDetailModal device={selectedDevice} onClose={() => setSelectedDevice(null)} />}
      {selectedAnomaly && <AnomalyDetailModal alert={selectedAnomaly} onClose={() => setSelectedAnomaly(null)} />}

      {/* Scan warning modal */}
      {showScanWarning && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={() => setShowScanWarning(false)}>
          <div className="bg-[#0d1220] border border-yellow-500/30 rounded-xl w-full max-w-md p-6 shadow-xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-yellow-500/20 rounded-lg"><AlertTriangle className="w-5 h-5 text-yellow-400" /></div>
              <h2 className="text-white font-semibold">スキャン実行の確認</h2>
            </div>
            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4 mb-4">
              <p className="text-yellow-300 text-sm leading-relaxed">
                パッシブスキャンのみ実行されます。ただし、一部の古いOT機器はネットワークスキャンに応答して<strong>停止または誤動作</strong>する場合があります。
              </p>
              <p className="text-yellow-300/70 text-xs mt-2">実行前に運用チームへの通知を推奨します。</p>
            </div>
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowScanWarning(false)} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>
              <button onClick={handleScan} className="px-4 py-2 rounded-lg bg-yellow-500/20 hover:bg-yellow-500/30 border border-yellow-500/30 text-yellow-300 text-sm font-medium transition-colors">
                パッシブスキャンを実行
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
