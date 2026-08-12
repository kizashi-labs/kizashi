'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiFetch } from '@/lib/api';
import {
  Plus,
  Trash2,
  CheckCircle2,
  XCircle,
  Loader2,
  Settings,
  X,
  ToggleLeft,
  ToggleRight,
  Ticket,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Zap,
} from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────────────────

type SOARType = 'jira' | 'servicenow';

interface SOARConfig {
  id: string;
  name: string;
  type: SOARType;
  enabled: boolean;
  config: Record<string, string>;
  min_severity: number;
  auto_create: boolean;
  created_at: string;
  updated_at: string;
}

interface SOARConfigForm {
  name: string;
  type: SOARType;
  enabled: boolean;
  config: Record<string, string>;
  min_severity: number;
  auto_create: boolean;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const JIRA_CONFIG_FIELDS: { key: string; label: string; placeholder: string; secret?: boolean }[] = [
  { key: 'url',       label: 'Jira URL',      placeholder: 'https://your-domain.atlassian.net' },
  { key: 'email',     label: 'メールアドレス', placeholder: 'user@example.com' },
  { key: 'api_token', label: 'APIトークン',   placeholder: 'Atlassian APIトークン', secret: true },
  { key: 'project',   label: 'プロジェクトキー', placeholder: 'EDR' },
];

const SERVICENOW_CONFIG_FIELDS: { key: string; label: string; placeholder: string; secret?: boolean }[] = [
  { key: 'url',      label: 'インスタンスURL', placeholder: 'https://instance.service-now.com' },
  { key: 'username', label: 'ユーザー名',      placeholder: 'admin' },
  { key: 'password', label: 'パスワード',      placeholder: 'パスワード', secret: true },
  { key: 'table',    label: 'テーブル名',      placeholder: 'incident (省略可)' },
];

const MIN_SEVERITY_OPTIONS = [
  { value: 1,  label: '重大度 1以上 (全て)' },
  { value: 4,  label: '重大度 4以上 (中以上)' },
  { value: 7,  label: '重大度 7以上 (高以上)' },
  { value: 9,  label: '重大度 9以上 (緊急のみ)' },
];

const SYSTEM_COLORS: Record<SOARType, string> = {
  jira:        'bg-blue-500/20 text-blue-300 border-blue-500/40',
  servicenow:  'bg-green-500/20 text-green-300 border-green-500/40',
};

const SYSTEM_LABELS: Record<SOARType, string> = {
  jira:        'Jira',
  servicenow:  'ServiceNow',
};

const INITIAL_FORM: SOARConfigForm = {
  name:         '',
  type:         'jira',
  enabled:      true,
  config:       {},
  min_severity: 7,
  auto_create:  false,
};

// ─── Sub Components ───────────────────────────────────────────────────────────

function SystemBadge({ type }: { type: SOARType }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${SYSTEM_COLORS[type]}`}>
      {SYSTEM_LABELS[type]}
    </span>
  );
}

function ConfigFieldsForm({
  type,
  config,
  onChange,
}: {
  type: SOARType;
  config: Record<string, string>;
  onChange: (key: string, value: string) => void;
}) {
  const fields = type === 'jira' ? JIRA_CONFIG_FIELDS : SERVICENOW_CONFIG_FIELDS;
  return (
    <>
      {fields.map((f) => (
        <div key={f.key}>
          <label className="block text-xs text-[#7d92b0] mb-1.5">
            {f.label}
            {f.key !== 'table' && <span className="text-red-400 ml-1">*</span>}
          </label>
          <input
            type={f.secret ? 'password' : 'text'}
            value={config[f.key] ?? ''}
            onChange={(e) => onChange(f.key, e.target.value)}
            placeholder={f.placeholder}
            autoComplete="off"
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-none focus:border-blue-500"
          />
        </div>
      ))}
    </>
  );
}

// ─── Add Config Modal ─────────────────────────────────────────────────────────

function AddConfigModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [form, setForm] = useState<SOARConfigForm>({ ...INITIAL_FORM, config: {} });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const handleConfigChange = (key: string, value: string) => {
    setForm((prev) => ({ ...prev, config: { ...prev.config, [key]: value } }));
  };

  const handleSubmit = async () => {
    if (!form.name.trim()) {
      setError('名前を入力してください');
      return;
    }
    setError('');
    setSubmitting(true);
    try {
      await apiFetch('/api/v1/soar/configs', {
        method: 'POST',
        body: JSON.stringify(form),
      });
      onCreated();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : '作成に失敗しました');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#111827] border border-blue-500/30 rounded-xl p-6 w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-sm font-semibold text-[#e2e8f4]">新しいSOAR連携を追加</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-4">
          {/* 名前 */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">
              名前 <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="本番Jira / ServiceNow-PROD"
              className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* タイプ */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">システムタイプ</label>
            <select
              value={form.type}
              onChange={(e) => setForm({ ...form, type: e.target.value as SOARType, config: {} })}
              className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:outline-none focus:border-blue-500"
            >
              <option value="jira">Jira</option>
              <option value="servicenow">ServiceNow</option>
            </select>
          </div>

          {/* 接続設定 */}
          <div className="pt-1 border-t border-[#1e2d42]">
            <p className="text-xs text-[#7d92b0] mb-3">接続設定</p>
            <div className="space-y-3">
              <ConfigFieldsForm
                type={form.type}
                config={form.config}
                onChange={handleConfigChange}
              />
            </div>
          </div>

          {/* トリガー設定 */}
          <div className="pt-1 border-t border-[#1e2d42]">
            <p className="text-xs text-[#7d92b0] mb-3">トリガー設定</p>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1.5">最小重大度</label>
                <select
                  value={form.min_severity}
                  onChange={(e) => setForm({ ...form, min_severity: Number(e.target.value) })}
                  className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:outline-none focus:border-blue-500"
                >
                  {MIN_SEVERITY_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-[#e2e8f4]">自動チケット起票</p>
                  <p className="text-xs text-[#7d92b0] mt-0.5">インシデント作成時に自動でチケットを起票します</p>
                </div>
                <button
                  type="button"
                  onClick={() => setForm({ ...form, auto_create: !form.auto_create })}
                  className="flex-shrink-0 ml-4"
                >
                  {form.auto_create ? (
                    <ToggleRight className="w-8 h-8 text-blue-400" />
                  ) : (
                    <ToggleLeft className="w-8 h-8 text-[#3a4d66]" />
                  )}
                </button>
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-[#e2e8f4]">有効化</p>
                  <p className="text-xs text-[#7d92b0] mt-0.5">この連携を有効にします</p>
                </div>
                <button
                  type="button"
                  onClick={() => setForm({ ...form, enabled: !form.enabled })}
                  className="flex-shrink-0 ml-4"
                >
                  {form.enabled ? (
                    <ToggleRight className="w-8 h-8 text-blue-400" />
                  ) : (
                    <ToggleLeft className="w-8 h-8 text-[#3a4d66]" />
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>

        {error && (
          <p className="mt-4 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
            {error}
          </p>
        )}

        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[#1e2d42] hover:bg-[#253550] text-[#e2e8f4] text-sm rounded-lg transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting}
            className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            追加
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Config Card ──────────────────────────────────────────────────────────────

function ConfigCard({
  config,
  onDelete,
  onToggle,
  onTest,
}: {
  config: SOARConfig;
  onDelete: (id: string) => void;
  onToggle: (id: string, enabled: boolean) => void;
  onTest: (id: string) => Promise<{ success: boolean; error?: string }>;
}) {
  const [expanded, setExpanded] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await onTest(config.id);
      setTestResult({
        success: result.success,
        message: result.success ? '接続テスト成功' : (result.error ?? '接続テスト失敗'),
      });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl overflow-hidden">
      {/* Card Header */}
      <div className="flex items-center justify-between px-5 py-4">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex-shrink-0">
            {config.enabled ? (
              <CheckCircle2 className="w-4 h-4 text-green-400" />
            ) : (
              <XCircle className="w-4 h-4 text-[#3a4d66]" />
            )}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-medium text-[#e2e8f4] truncate">{config.name}</span>
              <SystemBadge type={config.type} />
              {config.auto_create && (
                <span className="text-xs px-2 py-0.5 rounded-full border font-medium bg-purple-500/20 text-purple-300 border-purple-500/40 flex items-center gap-1">
                  <Zap className="w-3 h-3" />
                  自動起票
                </span>
              )}
            </div>
            <p className="text-xs text-[#7d92b0] mt-0.5">
              最小重大度: {config.min_severity} &nbsp;·&nbsp;
              {config.enabled ? '有効' : '無効'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={() => onToggle(config.id, !config.enabled)}
            title={config.enabled ? '無効化' : '有効化'}
            className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors p-1"
          >
            {config.enabled ? (
              <ToggleRight className="w-5 h-5 text-blue-400" />
            ) : (
              <ToggleLeft className="w-5 h-5" />
            )}
          </button>
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors p-1"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          <button
            onClick={() => onDelete(config.id)}
            className="text-[#7d92b0] hover:text-red-400 transition-colors p-1"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="border-t border-[#1e2d42] px-5 py-4 space-y-4">
          {/* Config fields */}
          <div className="grid grid-cols-2 gap-3">
            {Object.entries(config.config).map(([key, value]) => (
              <div key={key}>
                <p className="text-xs text-[#7d92b0]">{key}</p>
                <p className="text-sm text-[#e2e8f4] font-mono truncate">{String(value)}</p>
              </div>
            ))}
          </div>

          {/* Connection Test */}
          <div className="flex items-center gap-3 pt-2 border-t border-[#1e2d42]">
            <button
              onClick={handleTest}
              disabled={testing}
              className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#253550] disabled:opacity-50 text-[#e2e8f4] text-sm rounded-lg transition-colors"
            >
              {testing ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Settings className="w-4 h-4" />
              )}
              接続テスト
            </button>
            {testResult && (
              <div className={`flex items-center gap-2 text-sm ${testResult.success ? 'text-green-400' : 'text-red-400'}`}>
                {testResult.success ? (
                  <CheckCircle2 className="w-4 h-4" />
                ) : (
                  <XCircle className="w-4 h-4" />
                )}
                {testResult.message}
              </div>
            )}
          </div>

          <p className="text-xs text-[#3a4d66]">
            作成: {new Date(config.created_at).toLocaleString('ja-JP')} &nbsp;·&nbsp;
            更新: {new Date(config.updated_at).toLocaleString('ja-JP')}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SOARPage() {
  const qc = useQueryClient();
  const [showAddModal, setShowAddModal] = useState(false);

  const { data, isLoading } = useQuery<{ data: SOARConfig[] }>({
    queryKey: ['soar-configs'],
    queryFn: () => apiFetch<{ data: SOARConfig[] }>('/api/v1/soar/configs'),
  });

  const configs = data?.data ?? [];

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/soar/configs/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-configs'] }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiFetch(`/api/v1/soar/configs/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-configs'] }),
  });

  const handleTest = async (id: string): Promise<{ success: boolean; error?: string }> => {
    try {
      const result = await apiFetch<{ success: boolean; error?: string }>(
        `/api/v1/soar/configs/${id}/test`,
        { method: 'POST' }
      );
      return result;
    } catch (e: unknown) {
      return { success: false, error: e instanceof Error ? e.message : '接続テスト失敗' };
    }
  };

  const jiraConfigs = configs.filter((c) => c.type === 'jira');
  const serviceNowConfigs = configs.filter((c) => c.type === 'servicenow');

  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f4]">
      <div className="max-w-4xl mx-auto px-6 py-8">

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20">
              <Ticket className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-[#e2e8f4]">SOAR連携</h1>
              <p className="text-sm text-[#7d92b0] mt-0.5">
                Jira / ServiceNow へのインシデントチケット自動起票を設定します
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            連携を追加
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-5 py-4">
            <p className="text-xs text-[#7d92b0] mb-1">設定数</p>
            <p className="text-2xl font-bold text-[#e2e8f4]">{configs.length}</p>
          </div>
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-5 py-4">
            <p className="text-xs text-[#7d92b0] mb-1">有効</p>
            <p className="text-2xl font-bold text-green-400">
              {configs.filter((c) => c.enabled).length}
            </p>
          </div>
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-5 py-4">
            <p className="text-xs text-[#7d92b0] mb-1">自動起票</p>
            <p className="text-2xl font-bold text-purple-400">
              {configs.filter((c) => c.auto_create).length}
            </p>
          </div>
        </div>

        {/* Loading */}
        {isLoading && (
          <div className="flex items-center justify-center py-16">
            <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
          </div>
        )}

        {/* Empty State */}
        {!isLoading && configs.length === 0 && (
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl flex flex-col items-center justify-center py-16 text-center">
            <div className="p-3 bg-[#1e2d42] rounded-full mb-4">
              <Ticket className="w-6 h-6 text-[#7d92b0]" />
            </div>
            <p className="text-sm text-[#e2e8f4] font-medium">SOAR連携が設定されていません</p>
            <p className="text-xs text-[#7d92b0] mt-1 max-w-xs">
              「連携を追加」ボタンから Jira または ServiceNow との連携を設定してください
            </p>
            <button
              onClick={() => setShowAddModal(true)}
              className="mt-5 flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              最初の連携を追加
            </button>
          </div>
        )}

        {/* Jira Section */}
        {jiraConfigs.length > 0 && (
          <section className="mb-8">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-5 h-5 bg-blue-500/20 border border-blue-500/40 rounded flex items-center justify-center">
                <span className="text-blue-300 text-xs font-bold">J</span>
              </div>
              <h2 className="text-sm font-semibold text-[#e2e8f4]">Jira</h2>
              <span className="text-xs text-[#7d92b0]">{jiraConfigs.length}件</span>
            </div>
            <div className="space-y-3">
              {jiraConfigs.map((c) => (
                <ConfigCard
                  key={c.id}
                  config={c}
                  onDelete={(id) => deleteMutation.mutate(id)}
                  onToggle={(id, enabled) => toggleMutation.mutate({ id, enabled })}
                  onTest={handleTest}
                />
              ))}
            </div>
          </section>
        )}

        {/* ServiceNow Section */}
        {serviceNowConfigs.length > 0 && (
          <section className="mb-8">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-5 h-5 bg-green-500/20 border border-green-500/40 rounded flex items-center justify-center">
                <span className="text-green-300 text-xs font-bold">S</span>
              </div>
              <h2 className="text-sm font-semibold text-[#e2e8f4]">ServiceNow</h2>
              <span className="text-xs text-[#7d92b0]">{serviceNowConfigs.length}件</span>
            </div>
            <div className="space-y-3">
              {serviceNowConfigs.map((c) => (
                <ConfigCard
                  key={c.id}
                  config={c}
                  onDelete={(id) => deleteMutation.mutate(id)}
                  onToggle={(id, enabled) => toggleMutation.mutate({ id, enabled })}
                  onTest={handleTest}
                />
              ))}
            </div>
          </section>
        )}

        {/* Usage Note */}
        {configs.length > 0 && (
          <div className="bg-[#111827] border border-[#1e2d42] rounded-xl px-5 py-4">
            <div className="flex items-start gap-3">
              <ExternalLink className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-[#e2e8f4]">チケット手動起票</p>
                <p className="text-xs text-[#7d92b0] mt-1">
                  インシデント詳細ページから「チケット起票」ボタンを使用して、任意のSOAR連携に手動でチケットを作成できます。
                  自動起票が有効な場合、インシデント作成時に自動的にチケットが作成されます。
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Add Modal */}
      {showAddModal && (
        <AddConfigModal
          onClose={() => setShowAddModal(false)}
          onCreated={() => {
            setShowAddModal(false);
            qc.invalidateQueries({ queryKey: ['soar-configs'] });
          }}
        />
      )}
    </div>
  );
}
