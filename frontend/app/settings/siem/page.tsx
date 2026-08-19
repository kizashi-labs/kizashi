'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiFetch } from '@/lib/api';
import {
  Plus,
  Trash2,
  Radio,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
  Loader2,
  AlertTriangle,
  Settings,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

type SIEMType = 'syslog_cef' | 'splunk_hec' | 'elastic_ecs' | 'syslog_leef';
type Protocol = 'UDP' | 'TCP' | 'HTTPS';

interface SIEMTarget {
  id: string;
  name: string;
  type: SIEMType;
  host: string;
  port: number;
  protocol: Protocol;
  token: string;
  tls_enabled: boolean;
  index_name: string;
  min_severity: number;
  filter_rules: string[];
  filter_hostnames: string[];
  filter_mitre: string[];
  enabled: boolean;
  created_at: string;
  last_test?: string;
  last_test_ok?: boolean;
}

interface SIEMTargetForm {
  name: string;
  type: SIEMType;
  host: string;
  port: string;
  protocol: Protocol;
  token: string;
  tls_enabled: boolean;
  index_name: string;
  min_severity: number;
  filter_rules: string;     // カンマ区切りで入力
  filter_hostnames: string; // カンマ区切りで入力
  filter_mitre: string;     // カンマ区切りで入力
  enabled: boolean;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SIEM_TYPES: { value: SIEMType; label: string; description: string }[] = [
  { value: 'syslog_cef', label: 'Syslog/CEF', description: 'Common Event Format over Syslog' },
  { value: 'splunk_hec', label: 'Splunk HEC', description: 'Splunk HTTP Event Collector' },
  { value: 'elastic_ecs', label: 'Elastic ECS', description: 'Elastic Common Schema / Logstash' },
  { value: 'syslog_leef', label: 'Syslog/LEEF', description: 'Log Event Extended Format (QRadar)' },
];

const PROTOCOLS: Protocol[] = ['UDP', 'TCP', 'HTTPS'];

const DEFAULT_PORTS: Record<SIEMType, number> = {
  syslog_cef: 514,
  splunk_hec: 8088,
  elastic_ecs: 5044,
  syslog_leef: 514,
};

const DEFAULT_PROTOCOLS: Record<SIEMType, Protocol> = {
  syslog_cef: 'UDP',
  splunk_hec: 'HTTPS',
  elastic_ecs: 'TCP',
  syslog_leef: 'UDP',
};

const SEVERITY_LABELS: Record<number, { label: string; color: string }> = {
  0: { label: '情報 (0+)', color: 'text-blue-400' },
  25: { label: '低 (25+)', color: 'text-green-400' },
  50: { label: '中 (50+)', color: 'text-yellow-400' },
  75: { label: '高 (75+)', color: 'text-orange-400' },
  95: { label: '重大 (95+)', color: 'text-red-400' },
};

const INITIAL_FORM: SIEMTargetForm = {
  name: '',
  type: 'syslog_cef',
  host: '',
  port: '514',
  protocol: 'UDP',
  token: '',
  tls_enabled: false,
  index_name: '',
  min_severity: 0,
  filter_rules: '',
  filter_hostnames: '',
  filter_mitre: '',
  enabled: true,
};

// ─── API helpers ──────────────────────────────────────────────────────────────

async function fetchSIEMTargets(): Promise<SIEMTarget[]> {
  try {
    const json = await apiFetch<{ data: SIEMTarget[] }>('/api/v1/siem/targets');
    return json.data ?? [];
  } catch {
    return [];
  }
}

function toFilterArray(s: string): string[] {
  return s.split(',').map(v => v.trim()).filter(v => v.length > 0);
}

function toFilterString(arr: string[] | undefined): string {
  return (arr ?? []).join(', ');
}

async function createSIEMTarget(payload: SIEMTargetForm): Promise<SIEMTarget> {
  return apiFetch<SIEMTarget>('/api/v1/siem/targets', {
    method: 'POST',
    body: JSON.stringify({
      ...payload,
      port: parseInt(payload.port, 10),
      filter_rules:     toFilterArray(payload.filter_rules),
      filter_hostnames: toFilterArray(payload.filter_hostnames),
      filter_mitre:     toFilterArray(payload.filter_mitre),
    }),
  });
}

async function updateSIEMTarget(args: {
  id: string;
  payload: Partial<SIEMTargetForm>;
}): Promise<SIEMTarget> {
  const p = args.payload as SIEMTargetForm
  return apiFetch<SIEMTarget>(`/api/v1/siem/targets/${args.id}`, {
    method: 'PUT',
    body: JSON.stringify({
      ...p,
      port: parseInt(String(p.port), 10),
      filter_rules:     toFilterArray(p.filter_rules ?? ''),
      filter_hostnames: toFilterArray(p.filter_hostnames ?? ''),
      filter_mitre:     toFilterArray(p.filter_mitre ?? ''),
    }),
  });
}

async function deleteSIEMTarget(id: string): Promise<void> {
  await apiFetch<{ message: string }>(`/api/v1/siem/targets/${id}`, { method: 'DELETE' });
}

async function testSIEMTarget(id: string): Promise<{ ok: boolean; message: string }> {
  try {
    return await apiFetch<{ ok: boolean; message: string }>(`/api/v1/siem/targets/${id}/test`, { method: 'POST' });
  } catch {
    return { ok: false, message: 'テストリクエストが失敗しました' };
  }
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function TypeBadge({ type }: { type: SIEMType }) {
  const colors: Record<SIEMType, string> = {
    syslog_cef: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
    splunk_hec: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
    elastic_ecs: 'bg-green-500/20 text-green-300 border-green-500/40',
    syslog_leef: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
  };
  const labels: Record<SIEMType, string> = {
    syslog_cef: 'Syslog/CEF',
    splunk_hec: 'Splunk HEC',
    elastic_ecs: 'Elastic ECS',
    syslog_leef: 'Syslog/LEEF',
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${colors[type]}`}>
      {labels[type]}
    </span>
  );
}

function SeveritySlider({
  value,
  onChange,
}: {
  value: number;
  onChange: (v: number) => void;
}) {
  const steps = [0, 25, 50, 75, 95];
  const info = SEVERITY_LABELS[value] ?? SEVERITY_LABELS[0];
  return (
    <div>
      <div className="flex justify-between items-center mb-1.5">
        <label className="text-xs text-[#7d92b0]">最小重大度</label>
        <span className={`text-xs font-medium ${info.color}`}>{info.label}</span>
      </div>
      <input
        type="range"
        min={0}
        max={95}
        step={1}
        value={value}
        onChange={(e) => {
          const raw = parseInt(e.target.value, 10);
          // Snap to nearest step
          const nearest = steps.reduce((prev, curr) =>
            Math.abs(curr - raw) < Math.abs(prev - raw) ? curr : prev
          );
          onChange(nearest);
        }}
        className="w-full h-1.5 bg-[#1e2d42] rounded-full appearance-none cursor-pointer accent-blue-500"
      />
      <div className="flex justify-between text-xs text-[#7d92b0] mt-1">
        {steps.map((s) => (
          <span key={s} className={value === s ? 'text-blue-400 font-medium' : ''}>
            {s}
          </span>
        ))}
      </div>
    </div>
  );
}

function AddTargetForm({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState<SIEMTargetForm>(INITIAL_FORM);

  const createMutation = useMutation({
    mutationFn: createSIEMTarget,
    onSuccess: () => {
      onSaved();
      onClose();
    },
  });

  function setField<K extends keyof SIEMTargetForm>(key: K, value: SIEMTargetForm[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function handleTypeChange(type: SIEMType) {
    setForm((prev) => ({
      ...prev,
      type,
      port: String(DEFAULT_PORTS[type]),
      protocol: DEFAULT_PROTOCOLS[type],
      tls_enabled: DEFAULT_PROTOCOLS[type] === 'HTTPS',
    }));
  }

  const needsToken = form.type === 'splunk_hec' || form.type === 'elastic_ecs';
  const needsIndex = form.type === 'splunk_hec' || form.type === 'elastic_ecs';

  return (
    <div className="bg-[#111827] border border-blue-500/30 rounded-xl p-6 mb-6">
      <div className="flex items-center justify-between mb-5">
        <h2 className="text-sm font-semibold text-[#e2e8f4]">新しいSIEMターゲットを追加</h2>
        <button onClick={onClose} className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Name */}
        <div className="col-span-2">
          <label className="block text-xs text-[#7d92b0] mb-1.5">
            名前 <span className="text-red-400">*</span>
          </label>
          <input
            type="text"
            value={form.name}
            onChange={(e) => setField('name', e.target.value)}
            placeholder="例: Production SIEM"
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-hidden focus:border-blue-500"
          />
        </div>

        {/* Type */}
        <div>
          <label className="block text-xs text-[#7d92b0] mb-1.5">タイプ</label>
          <select
            value={form.type}
            onChange={(e) => handleTypeChange(e.target.value as SIEMType)}
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
          >
            {SIEM_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label} — {t.description}
              </option>
            ))}
          </select>
        </div>

        {/* Protocol */}
        <div>
          <label className="block text-xs text-[#7d92b0] mb-1.5">プロトコル</label>
          <select
            value={form.protocol}
            onChange={(e) => setField('protocol', e.target.value as Protocol)}
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
          >
            {PROTOCOLS.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </div>

        {/* Host */}
        <div>
          <label className="block text-xs text-[#7d92b0] mb-1.5">
            ホスト / IPアドレス <span className="text-red-400">*</span>
          </label>
          <input
            type="text"
            value={form.host}
            onChange={(e) => setField('host', e.target.value)}
            placeholder="192.168.1.100 または siem.example.com"
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-hidden focus:border-blue-500"
          />
        </div>

        {/* Port */}
        <div>
          <label className="block text-xs text-[#7d92b0] mb-1.5">ポート</label>
          <input
            type="number"
            value={form.port}
            onChange={(e) => setField('port', e.target.value)}
            min={1}
            max={65535}
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:outline-hidden focus:border-blue-500"
          />
        </div>

        {/* Token / API Key */}
        {needsToken && (
          <div className="col-span-2">
            <label className="block text-xs text-[#7d92b0] mb-1.5">
              {form.type === 'splunk_hec' ? 'HECトークン' : 'APIキー / Bearer Token'}
            </label>
            <input
              type="password"
              value={form.token}
              onChange={(e) => setField('token', e.target.value)}
              placeholder="••••••••••••••••"
              className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-hidden focus:border-blue-500 font-mono"
            />
          </div>
        )}

        {/* Index Name */}
        {needsIndex && (
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">インデックス名</label>
            <input
              type="text"
              value={form.index_name}
              onChange={(e) => setField('index_name', e.target.value)}
              placeholder={form.type === 'splunk_hec' ? 'edr_events' : 'edr-events-*'}
              className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-hidden focus:border-blue-500"
            />
          </div>
        )}

        {/* TLS */}
        <div className={needsIndex ? '' : 'col-span-2'}>
          <label className="block text-xs text-[#7d92b0] mb-1.5">セキュリティ</label>
          <label className="flex items-center gap-2 cursor-pointer">
            <div
              onClick={() => setField('tls_enabled', !form.tls_enabled)}
              className={`relative w-9 h-5 rounded-full transition-colors ${
                form.tls_enabled ? 'bg-blue-600' : 'bg-[#1e2d42]'
              }`}
            >
              <div
                className={`absolute top-0.5 left-0.5 w-4 h-4 bg-[#e2e8f4] rounded-full shadow-sm transition-transform ${
                  form.tls_enabled ? 'translate-x-4' : 'translate-x-0'
                }`}
              />
            </div>
            <span className="text-xs text-[#e2e8f4]">TLS/SSL を有効化</span>
          </label>
        </div>

        {/* Min Severity */}
        <div className="col-span-2">
          <SeveritySlider
            value={form.min_severity}
            onChange={(v) => setField('min_severity', v)}
          />
        </div>

        {/* Advanced filters */}
        <div className="col-span-2 border-t border-[#1e2d42] pt-4 mt-1">
          <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-widest mb-3">
            詳細フィルター（空欄=全て転送）
          </p>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">
                ルール名フィルター <span className="text-[#3d5068] font-normal">（カンマ区切りで複数指定可）</span>
              </label>
              <input
                type="text"
                value={form.filter_rules}
                onChange={e => setField('filter_rules', e.target.value)}
                placeholder="例: Mimikatz_Strings, PowerShell_Empire"
                className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-blue-500/50"
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">
                端末ホスト名フィルター <span className="text-[#3d5068] font-normal">（カンマ区切りで複数指定可）</span>
              </label>
              <input
                type="text"
                value={form.filter_hostnames}
                onChange={e => setField('filter_hostnames', e.target.value)}
                placeholder="例: server01, web-prod, db-primary"
                className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-blue-500/50"
              />
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">
                MITREテクニックフィルター <span className="text-[#3d5068] font-normal">（カンマ区切りで複数指定可）</span>
              </label>
              <input
                type="text"
                value={form.filter_mitre}
                onChange={e => setField('filter_mitre', e.target.value)}
                placeholder="例: T1059, T1003, T1078"
                className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#3d5068] focus:outline-hidden focus:border-blue-500/50"
              />
            </div>
          </div>
        </div>

        {/* Enabled toggle */}
        <div className="col-span-2">
          <label className="flex items-center gap-2 cursor-pointer">
            <div
              onClick={() => setField('enabled', !form.enabled)}
              className={`relative w-9 h-5 rounded-full transition-colors ${
                form.enabled ? 'bg-blue-600' : 'bg-[#1e2d42]'
              }`}
            >
              <div
                className={`absolute top-0.5 left-0.5 w-4 h-4 bg-[#e2e8f4] rounded-full shadow-sm transition-transform ${
                  form.enabled ? 'translate-x-4' : 'translate-x-0'
                }`}
              />
            </div>
            <span className="text-xs text-[#e2e8f4]">このターゲットを有効にする</span>
          </label>
        </div>
      </div>

      {createMutation.isError && (
        <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-xs">
          {(createMutation.error as Error).message}
        </div>
      )}

      <div className="flex gap-3 mt-6">
        <button
          onClick={onClose}
          className="flex-1 px-4 py-2.5 bg-[#161f33] hover:bg-[#1e2d42] rounded-lg text-sm font-medium transition-colors"
        >
          キャンセル
        </button>
        <button
          onClick={() => createMutation.mutate(form)}
          disabled={!form.name.trim() || !form.host.trim() || createMutation.isPending}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
        >
          {createMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
          追加する
        </button>
      </div>
    </div>
  );
}

function TargetRow({
  target,
  onDelete,
  onTest,
  onToggle,
}: {
  target: SIEMTarget;
  onDelete: (id: string) => void;
  onTest: (id: string) => void;
  onToggle: (id: string, enabled: boolean) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testSIEMTarget(target.id);
      setTestResult(res);
    } catch {
      setTestResult({ ok: false, message: '接続テストに失敗しました' });
    } finally {
      setTesting(false);
    }
  }

  const severityInfo =
    SEVERITY_LABELS[target.min_severity] ??
    Object.entries(SEVERITY_LABELS)
      .reverse()
      .find(([k]) => target.min_severity >= parseInt(k, 10))?.[1] ??
    SEVERITY_LABELS[0];

  return (
    <div
      className={`bg-[#111827] border rounded-lg transition-colors ${
        target.enabled ? 'border-[#1e2d42]' : 'border-[#1e2d42] opacity-60'
      }`}
    >
      <div className="p-4">
        <div className="flex items-center gap-3">
          {/* Status indicator */}
          <div
            className={`w-2 h-2 rounded-full shrink-0 ${
              !target.enabled
                ? 'bg-[#7d92b0]'
                : target.last_test_ok === true
                ? 'bg-green-400'
                : target.last_test_ok === false
                ? 'bg-red-400'
                : 'bg-yellow-400'
            }`}
          />

          {/* Name & type */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-semibold text-[#e2e8f4]">{target.name}</span>
              <TypeBadge type={target.type} />
              {!target.enabled && (
                <span className="text-xs text-[#7d92b0] bg-[#161f33] px-1.5 py-0.5 rounded-full">
                  無効
                </span>
              )}
            </div>
            <div className="flex items-center gap-3 mt-0.5 text-xs text-[#7d92b0]">
              <span className="font-mono">
                {target.protocol}://{target.host}:{target.port}
              </span>
              {target.tls_enabled && (
                <span className="text-green-400 flex items-center gap-0.5">
                  <Wifi className="w-3 h-3" />
                  TLS
                </span>
              )}
              <span className={severityInfo.color}>{severityInfo.label}</span>
              {target.index_name && (
                <span className="text-[#7d92b0]">idx: {target.index_name}</span>
              )}
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 shrink-0">
            {/* Enable toggle */}
            <div
              onClick={() => onToggle(target.id, !target.enabled)}
              className={`relative w-8 h-4 rounded-full cursor-pointer transition-colors ${
                target.enabled ? 'bg-blue-600' : 'bg-[#1e2d42]'
              }`}
            >
              <div
                className={`absolute top-0.5 left-0.5 w-3 h-3 bg-[#e2e8f4] rounded-full shadow-sm transition-transform ${
                  target.enabled ? 'translate-x-4' : 'translate-x-0'
                }`}
              />
            </div>

            {/* Test button */}
            <button
              onClick={handleTest}
              disabled={testing}
              title="接続テスト"
              className="flex items-center gap-1 px-2 py-1.5 bg-[#161f33] hover:bg-[#1e2d42] rounded-lg text-xs text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
            >
              {testing ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Radio className="w-3.5 h-3.5" />
              )}
              テスト
            </button>

            {/* Expand */}
            <button
              onClick={() => setExpanded((v) => !v)}
              className="p-1.5 text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
            >
              {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>

            {/* Delete */}
            {confirmDelete ? (
              <div className="flex items-center gap-1">
                <button
                  onClick={() => onDelete(target.id)}
                  className="px-2 py-1 bg-red-600 hover:bg-red-700 rounded-sm text-xs font-medium transition-colors"
                >
                  削除確認
                </button>
                <button
                  onClick={() => setConfirmDelete(false)}
                  className="p-1.5 text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirmDelete(true)}
                className="p-1.5 text-[#7d92b0] hover:text-red-400 transition-colors"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Test result */}
        {testResult && (
          <div
            className={`mt-3 flex items-center gap-2 text-xs p-2 rounded-lg ${
              testResult.ok
                ? 'bg-green-500/10 border border-green-500/30 text-green-400'
                : 'bg-red-500/10 border border-red-500/30 text-red-400'
            }`}
          >
            {testResult.ok ? (
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
            ) : (
              <XCircle className="w-3.5 h-3.5 shrink-0" />
            )}
            {testResult.message}
          </div>
        )}
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-[#1e2d42] px-4 py-3">
          <div className="grid grid-cols-3 gap-3 text-xs">
            <div>
              <span className="text-[#7d92b0] block mb-0.5">タイプ</span>
              <TypeBadge type={target.type} />
            </div>
            <div>
              <span className="text-[#7d92b0] block mb-0.5">プロトコル</span>
              <span className="text-[#e2e8f4] font-mono">{target.protocol}</span>
            </div>
            <div>
              <span className="text-[#7d92b0] block mb-0.5">TLS</span>
              <span className={target.tls_enabled ? 'text-green-400' : 'text-[#7d92b0]'}>
                {target.tls_enabled ? '有効' : '無効'}
              </span>
            </div>
            <div>
              <span className="text-[#7d92b0] block mb-0.5">エンドポイント</span>
              <span className="text-[#e2e8f4] font-mono">
                {target.host}:{target.port}
              </span>
            </div>
            {target.index_name && (
              <div>
                <span className="text-[#7d92b0] block mb-0.5">インデックス</span>
                <span className="text-[#e2e8f4]">{target.index_name}</span>
              </div>
            )}
            <div>
              <span className="text-[#7d92b0] block mb-0.5">最小重大度</span>
              <span className={severityInfo.color}>{target.min_severity}</span>
            </div>
            {target.token && (
              <div>
                <span className="text-[#7d92b0] block mb-0.5">トークン</span>
                <span className="text-[#e2e8f4] font-mono">
                  {'•'.repeat(12)}
                </span>
              </div>
            )}
            <div>
              <span className="text-[#7d92b0] block mb-0.5">追加日</span>
              <span className="text-[#e2e8f4]">
                {new Date(target.created_at).toLocaleDateString('ja-JP')}
              </span>
            </div>
            {target.last_test && (
              <div>
                <span className="text-[#7d92b0] block mb-0.5">最終テスト</span>
                <span
                  className={target.last_test_ok ? 'text-green-400' : 'text-red-400'}
                >
                  {new Date(target.last_test).toLocaleString('ja-JP')}
                </span>
              </div>
            )}
          </div>
          {/* Filter display */}
          {((target.filter_rules?.length ?? 0) > 0 || (target.filter_hostnames?.length ?? 0) > 0 || (target.filter_mitre?.length ?? 0) > 0) && (
            <div className="mt-3 pt-3 border-t border-[#1e2d42] space-y-1.5">
              <p className="text-[10px] font-semibold text-[#7d92b0] uppercase tracking-widest">詳細フィルター（ホワイトリスト）</p>
              {(target.filter_rules?.length ?? 0) > 0 && (
                <div className="flex gap-2 text-xs"><span className="text-[#7d92b0] w-20 shrink-0">ルール名</span><span className="text-[#e2e8f4] font-mono">{target.filter_rules.join(', ')}</span></div>
              )}
              {(target.filter_hostnames?.length ?? 0) > 0 && (
                <div className="flex gap-2 text-xs"><span className="text-[#7d92b0] w-20 shrink-0">端末</span><span className="text-[#e2e8f4] font-mono">{target.filter_hostnames.join(', ')}</span></div>
              )}
              {(target.filter_mitre?.length ?? 0) > 0 && (
                <div className="flex gap-2 text-xs"><span className="text-[#7d92b0] w-20 shrink-0">MITRE</span><span className="text-[#e2e8f4] font-mono">{target.filter_mitre.join(', ')}</span></div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SIEMSettingsPage() {
  const queryClient = useQueryClient();
  const [showAddForm, setShowAddForm] = useState(false);

  const { data: targets = [], isLoading, isError } = useQuery({
    queryKey: ['siem-targets'],
    queryFn: fetchSIEMTargets,
  });

  const deleteMutation = useMutation({
    mutationFn: deleteSIEMTarget,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['siem-targets'] }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateSIEMTarget({ id, payload: { enabled } }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['siem-targets'] }),
  });

  const enabledCount = targets.filter((t) => t.enabled).length;

  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f4]">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* Page Header */}
      <div className="border-b border-[#1e2d42] px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-[#161f33] rounded-lg">
              <Settings className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-[#e2e8f4]">SIEM転送設定</h1>
              <p className="text-sm text-[#7d92b0] mt-0.5">
                外部SIEMシステムへのイベント転送ターゲットを管理します
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowAddForm((v) => !v)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              showAddForm
                ? 'bg-[#161f33] text-[#7d92b0]'
                : 'bg-blue-600 hover:bg-blue-700 text-white'
            }`}
          >
            <Plus className="w-4 h-4" />
            ターゲットを追加
          </button>
        </div>

        {/* Stats bar */}
        {targets.length > 0 && (
          <div className="flex items-center gap-6 mt-4 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-[#7d92b0]">ターゲット数:</span>
              <span className="font-medium text-[#e2e8f4]">{targets.length}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-green-400 rounded-full" />
              <span className="text-[#7d92b0]">有効:</span>
              <span className="font-medium text-green-400">{enabledCount}</span>
            </div>
            <div className="flex items-center gap-2">
              <WifiOff className="w-3.5 h-3.5 text-[#7d92b0]" />
              <span className="text-[#7d92b0]">無効:</span>
              <span className="font-medium text-[#7d92b0]">{targets.length - enabledCount}</span>
            </div>
          </div>
        )}
      </div>

      <div className="p-6">
        {/* Add form */}
        {showAddForm && (
          <AddTargetForm
            onClose={() => setShowAddForm(false)}
            onSaved={() => queryClient.invalidateQueries({ queryKey: ['siem-targets'] })}
          />
        )}

        {/* Loading */}
        {isLoading && (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="h-20 bg-[#111827] border border-[#1e2d42] rounded-lg animate-pulse"
              />
            ))}
          </div>
        )}

        {/* Error */}
        {isError && (
          <div className="bg-[#111827] border border-red-500/30 rounded-lg p-6 flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            <div>
              <p className="text-sm font-medium text-red-400">データの取得に失敗しました</p>
              <p className="text-xs text-[#7d92b0] mt-0.5">
                サーバーへの接続を確認してください
              </p>
            </div>
          </div>
        )}

        {/* Target list */}
        {!isLoading && !isError && targets.length === 0 && !showAddForm && (
          <div className="bg-[#111827] border border-[#1e2d42] rounded-lg p-12 text-center">
            <div className="w-12 h-12 bg-[#161f33] rounded-full flex items-center justify-center mx-auto mb-4">
              <Radio className="w-6 h-6 text-[#7d92b0]" />
            </div>
            <p className="text-[#e2e8f4] font-medium mb-1">SIEMターゲットがありません</p>
            <p className="text-sm text-[#7d92b0] mb-4">
              イベントを転送するSIEMシステムを追加してください
            </p>
            <button
              onClick={() => setShowAddForm(true)}
              className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm font-medium transition-colors"
            >
              <Plus className="w-4 h-4" />
              最初のターゲットを追加
            </button>
          </div>
        )}

        {!isLoading && targets.length > 0 && (
          <>
            {/* Section info */}
            <div className="flex items-center gap-2 mb-4">
              <h2 className="text-sm font-medium text-[#7d92b0]">
                設定済みターゲット ({targets.length})
              </h2>
            </div>

            <div className="space-y-3">
              {targets.map((target) => (
                <TargetRow
                  key={target.id}
                  target={target}
                  onDelete={(id) => deleteMutation.mutate(id)}
                  onTest={(id) => void id}
                  onToggle={(id, enabled) => toggleMutation.mutate({ id, enabled })}
                />
              ))}
            </div>

            {deleteMutation.isError && (
              <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-xs">
                {(deleteMutation.error as Error).message}
              </div>
            )}
          </>
        )}

        {/* Help section */}
        <div className="mt-8 bg-[#111827] border border-[#1e2d42] rounded-lg p-5">
          <h3 className="text-sm font-semibold text-[#e2e8f4] mb-3">設定ガイド</h3>
          <div className="grid grid-cols-2 gap-4">
            {SIEM_TYPES.map((t) => (
              <div key={t.value} className="flex items-start gap-3">
                <TypeBadge type={t.value} />
                <div>
                  <p className="text-xs text-[#7d92b0]">{t.description}</p>
                  <p className="text-xs text-[#7d92b0] mt-0.5">
                    デフォルトポート: {DEFAULT_PORTS[t.value]} ({DEFAULT_PROTOCOLS[t.value]})
                  </p>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t border-[#1e2d42] text-xs text-[#7d92b0]">
            <p>
              <span className="text-[#e2e8f4] font-medium">最小重大度:</span>{' '}
              設定した値以上のアラートのみが転送されます。0 を設定するとすべてのイベントが転送されます。
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
