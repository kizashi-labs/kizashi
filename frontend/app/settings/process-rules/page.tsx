'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiFetch } from '@/lib/api';
import {
  Plus,
  Trash2,
  X,
  Loader2,
  ToggleLeft,
  ToggleRight,
  AlertTriangle,
  ShieldBan,
  BellRing,
  ShieldAlert,
  Pencil,
  Terminal,
} from 'lucide-react';

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

type RuleType  = 'allow' | 'deny';
type ScopeType = 'all' | 'group' | 'agent';
type ActionType = 'alert' | 'block' | 'alert_and_block';
type Severity  = 'low' | 'medium' | 'high' | 'critical';

interface ProcessBlockRule {
  id: string;
  name: string;
  process_name: string;
  rule_type: RuleType;
  scope: ScopeType;
  scope_id?: string;
  action: ActionType;
  enabled: boolean;
  severity: Severity;
  created_at: string;
}

interface ListResponse {
  data: ProcessBlockRule[];
  total: number;
}

interface ProcessBlockRuleForm {
  name: string;
  process_name: string;
  rule_type: RuleType;
  scope: ScopeType;
  scope_id: string;
  action: ActionType;
  enabled: boolean;
  severity: Severity;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const INITIAL_FORM: ProcessBlockRuleForm = {
  name: '',
  process_name: '',
  rule_type: 'deny',
  scope: 'all',
  scope_id: '',
  action: 'alert',
  enabled: true,
  severity: 'high',
};

const ACTION_STYLES: Record<ActionType, string> = {
  alert:           'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
  block:           'bg-red-500/20 text-red-300 border-red-500/40',
  alert_and_block: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
};

const ACTION_LABELS: Record<ActionType, string> = {
  alert:           'アラートのみ',
  block:           'ブロック',
  alert_and_block: 'アラート＋ブロック',
};

const SEVERITY_STYLES: Record<Severity, string> = {
  low:      'bg-green-500/20 text-green-300 border-green-500/40',
  medium:   'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
  high:     'bg-orange-500/20 text-orange-300 border-orange-500/40',
  critical: 'bg-red-500/20 text-red-300 border-red-500/40',
};

const SEVERITY_LABELS: Record<Severity, string> = {
  low:      '低',
  medium:   '中',
  high:     '高',
  critical: '重大',
};

// ─── Badge Components ─────────────────────────────────────────────────────────

function ActionBadge({ action }: { action: ActionType }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium flex items-center gap-1 w-fit ${ACTION_STYLES[action]}`}>
      {action === 'alert' ? (
        <BellRing className="w-3 h-3" />
      ) : action === 'block' ? (
        <ShieldBan className="w-3 h-3" />
      ) : (
        <ShieldAlert className="w-3 h-3" />
      )}
      {ACTION_LABELS[action]}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium w-fit ${SEVERITY_STYLES[severity]}`}>
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

function RuleTypeBadge({ ruleType }: { ruleType: RuleType }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium w-fit
      ${ruleType === 'deny'
        ? 'bg-red-500/10 text-red-300 border-red-500/30'
        : 'bg-green-500/10 text-green-300 border-green-500/30'
      }`}>
      {ruleType === 'deny' ? '拒否' : '許可'}
    </span>
  );
}

// ─── Rule Form Modal ──────────────────────────────────────────────────────────

function RuleFormModal({
  title,
  initial,
  onClose,
  onSubmit,
  isPending,
}: {
  title: string;
  initial: ProcessBlockRuleForm;
  onClose: () => void;
  onSubmit: (form: ProcessBlockRuleForm) => void;
  isPending: boolean;
}) {
  const [form, setForm] = useState<ProcessBlockRuleForm>({ ...initial });
  const [error, setError] = useState('');

  const handleSubmit = () => {
    if (!form.name.trim()) {
      setError('ルール名を入力してください');
      return;
    }
    if (!form.process_name.trim()) {
      setError('プロセス名を入力してください');
      return;
    }
    if (form.scope !== 'all' && !form.scope_id.trim()) {
      setError('スコープIDを入力してください');
      return;
    }
    setError('');
    onSubmit(form);
  };

  const set = <K extends keyof ProcessBlockRuleForm>(k: K, v: ProcessBlockRuleForm[K]) =>
    setForm((f) => ({ ...f, [k]: v }));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-6 w-full max-w-lg mx-4 shadow-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-sm font-semibold text-[#e2e8f4] flex items-center gap-2">
            <Terminal className="w-4 h-4 text-blue-400" />
            {title}
          </h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">
              ルール名 <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => set('name', e.target.value)}
              placeholder="cmd.exe ブロック"
              autoComplete="off"
              className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#3a4d66] focus:outline-hidden focus:border-blue-500"
            />
          </div>

          {/* Process Name */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">
              プロセス名またはグロブ <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={form.process_name}
              onChange={(e) => set('process_name', e.target.value)}
              placeholder="cmd.exe  または  pow*"
              autoComplete="off"
              spellCheck={false}
              className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#3a4d66] focus:outline-hidden focus:border-blue-500 font-mono"
            />
            <p className="text-xs text-[#3a4d66] mt-1">
              完全一致 (例: <code className="font-mono">cmd.exe</code>) またはグロブ (例: <code className="font-mono">pow*</code>)
            </p>
          </div>

          {/* Rule Type */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-2">ルール種別</label>
            <div className="grid grid-cols-2 gap-3">
              {(['deny', 'allow'] as RuleType[]).map((rt) => (
                <button
                  key={rt}
                  type="button"
                  onClick={() => set('rule_type', rt)}
                  className={`px-3 py-2.5 rounded-lg border text-sm font-medium transition-colors
                    ${form.rule_type === rt
                      ? rt === 'deny'
                        ? 'bg-red-500/20 border-red-500/50 text-red-300'
                        : 'bg-green-500/20 border-green-500/50 text-green-300'
                      : 'bg-[#0d1525] border-[#1e2d42] text-[#7d92b0] hover:border-[#2a3d5a]'
                    }`}
                >
                  {rt === 'deny' ? '拒否 (Deny)' : '許可 (Allow)'}
                </button>
              ))}
            </div>
          </div>

          {/* Action */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-2">アクション</label>
            <div className="grid grid-cols-3 gap-2">
              {(['alert', 'block', 'alert_and_block'] as ActionType[]).map((a) => (
                <button
                  key={a}
                  type="button"
                  onClick={() => set('action', a)}
                  className={`flex flex-col items-center gap-1.5 px-2 py-3 rounded-lg border text-xs font-medium transition-colors
                    ${form.action === a
                      ? a === 'block'
                        ? 'bg-red-500/20 border-red-500/50 text-red-300'
                        : a === 'alert_and_block'
                          ? 'bg-orange-500/20 border-orange-500/50 text-orange-300'
                          : 'bg-yellow-500/20 border-yellow-500/50 text-yellow-300'
                      : 'bg-[#0d1525] border-[#1e2d42] text-[#7d92b0] hover:border-[#2a3d5a]'
                    }`}
                >
                  {a === 'alert' ? (
                    <BellRing className="w-4 h-4" />
                  ) : a === 'block' ? (
                    <ShieldBan className="w-4 h-4" />
                  ) : (
                    <ShieldAlert className="w-4 h-4" />
                  )}
                  {ACTION_LABELS[a]}
                </button>
              ))}
            </div>
            {(form.action === 'block' || form.action === 'alert_and_block') && (
              <p className="text-xs text-red-400 mt-2 flex items-start gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                プロセスを強制終了します
              </p>
            )}
          </div>

          {/* Severity */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-2">重大度</label>
            <div className="grid grid-cols-4 gap-2">
              {(['low', 'medium', 'high', 'critical'] as Severity[]).map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => set('severity', s)}
                  className={`px-2 py-2 rounded-lg border text-xs font-medium transition-colors
                    ${form.severity === s
                      ? SEVERITY_STYLES[s]
                      : 'bg-[#0d1525] border-[#1e2d42] text-[#7d92b0] hover:border-[#2a3d5a]'
                    }`}
                >
                  {SEVERITY_LABELS[s]}
                </button>
              ))}
            </div>
          </div>

          {/* Scope */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-2">適用スコープ</label>
            <div className="grid grid-cols-3 gap-2">
              {(['all', 'group', 'agent'] as ScopeType[]).map((sc) => (
                <button
                  key={sc}
                  type="button"
                  onClick={() => set('scope', sc)}
                  className={`px-2 py-2.5 rounded-lg border text-xs font-medium transition-colors
                    ${form.scope === sc
                      ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
                      : 'bg-[#0d1525] border-[#1e2d42] text-[#7d92b0] hover:border-[#2a3d5a]'
                    }`}
                >
                  {sc === 'all' ? '全エージェント' : sc === 'group' ? 'グループ' : 'エージェント'}
                </button>
              ))}
            </div>
          </div>

          {/* Scope ID */}
          {form.scope !== 'all' && (
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">
                {form.scope === 'group' ? 'グループID' : 'エージェントID'}
                <span className="text-red-400"> *</span>
              </label>
              <input
                type="text"
                value={form.scope_id}
                onChange={(e) => set('scope_id', e.target.value)}
                placeholder={form.scope === 'group' ? 'グループUUID' : 'エージェントUUID'}
                autoComplete="off"
                spellCheck={false}
                className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#3a4d66] focus:outline-hidden focus:border-blue-500 font-mono"
              />
            </div>
          )}

          {/* Enable Toggle */}
          <div className="flex items-center justify-between pt-1">
            <div>
              <p className="text-sm text-[#e2e8f4]">有効化</p>
              <p className="text-xs text-[#7d92b0] mt-0.5">このルールを有効にします</p>
            </div>
            <button
              type="button"
              onClick={() => set('enabled', !form.enabled)}
              className="shrink-0 ml-4"
            >
              {form.enabled ? (
                <ToggleRight className="w-8 h-8 text-blue-400" />
              ) : (
                <ToggleLeft className="w-8 h-8 text-[#3a4d66]" />
              )}
            </button>
          </div>
        </div>

        {/* Error */}
        {error && (
          <p className="mt-4 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
            {error}
          </p>
        )}

        {/* Footer */}
        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[#1e2d42] hover:bg-[#253550] text-[#e2e8f4] text-sm rounded-lg transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={handleSubmit}
            disabled={isPending}
            className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Plus className="w-4 h-4" />
            )}
            保存
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Delete Confirm Dialog ────────────────────────────────────────────────────

function DeleteConfirmDialog({
  ruleName,
  onConfirm,
  onCancel,
  isPending,
}: {
  ruleName: string;
  onConfirm: () => void;
  onCancel: () => void;
  isPending: boolean;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111827] border border-red-500/30 rounded-xl p-6 w-full max-w-sm mx-4 shadow-2xl">
        <div className="flex items-start gap-3 mb-4">
          <div className="p-2 bg-red-500/10 rounded-lg border border-red-500/20 shrink-0">
            <Trash2 className="w-4 h-4 text-red-400" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-[#e2e8f4]">ルールを削除</h2>
            <p className="text-xs text-[#7d92b0] mt-1">
              <span className="text-[#e2e8f4] font-medium">{ruleName}</span> を削除しますか？この操作は元に戻せません。
            </p>
          </div>
        </div>
        <div className="flex gap-3">
          <button
            onClick={onCancel}
            className="flex-1 px-4 py-2 bg-[#1e2d42] hover:bg-[#253550] text-[#e2e8f4] text-sm rounded-lg transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            disabled={isPending}
            className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white text-sm rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
            削除
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Rule Card ────────────────────────────────────────────────────────────────

function RuleCard({
  rule,
  onEdit,
  onDelete,
  onToggle,
}: {
  rule: ProcessBlockRule;
  onEdit: (rule: ProcessBlockRule) => void;
  onDelete: (rule: ProcessBlockRule) => void;
  onToggle: (id: string) => void;
}) {
  return (
    <div
      className={`bg-[#0d1525] border rounded-xl px-5 py-4 transition-colors
        ${rule.action === 'block' || rule.action === 'alert_and_block'
          ? 'border-red-500/20 hover:border-red-500/40'
          : 'border-[#1e2d42] hover:border-[#2a3d5a]'
        }
        ${!rule.enabled ? 'opacity-60' : ''}
      `}
    >
      <div className="flex items-start justify-between gap-3">
        {/* Left: info */}
        <div className="min-w-0 space-y-2">
          <p className="text-sm font-medium text-[#e2e8f4] truncate">{rule.name}</p>
          <p className="text-xs font-mono text-blue-300 bg-blue-900/20 px-2 py-0.5 rounded-sm w-fit">
            {rule.process_name}
          </p>
          <div className="flex items-center gap-2 flex-wrap">
            <RuleTypeBadge ruleType={rule.rule_type} />
            <ActionBadge action={rule.action} />
            <SeverityBadge severity={rule.severity} />
            {rule.scope !== 'all' && (
              <span className="text-xs px-2 py-0.5 rounded-full border bg-blue-500/10 text-blue-300 border-blue-500/30">
                {rule.scope === 'group' ? 'グループ' : 'エージェント'}: {rule.scope_id}
              </span>
            )}
            {!rule.enabled && (
              <span className="text-xs px-2 py-0.5 rounded-full border bg-[#1e2d42] text-[#7d92b0] border-[#2a3d5a]">
                無効
              </span>
            )}
          </div>
          <p className="text-xs text-[#3a4d66]">
            作成: {new Date(rule.created_at).toLocaleString('ja-JP')}
          </p>
        </div>

        {/* Right: actions */}
        <div className="flex items-center gap-1 shrink-0">
          <button
            onClick={() => onToggle(rule.id)}
            title={rule.enabled ? '無効化' : '有効化'}
            className="p-1.5 text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
          >
            {rule.enabled ? (
              <ToggleRight className="w-5 h-5 text-blue-400" />
            ) : (
              <ToggleLeft className="w-5 h-5" />
            )}
          </button>
          <button
            onClick={() => onEdit(rule)}
            title="編集"
            className="p-1.5 text-[#7d92b0] hover:text-blue-400 transition-colors rounded-lg hover:bg-blue-900/20"
          >
            <Pencil className="w-4 h-4" />
          </button>
          <button
            onClick={() => onDelete(rule)}
            title="削除"
            className="p-1.5 text-[#7d92b0] hover:text-red-400 transition-colors rounded-lg hover:bg-red-900/20"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ProcessRulesPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editingRule, setEditingRule] = useState<ProcessBlockRule | null>(null);
  const [deletingRule, setDeletingRule] = useState<ProcessBlockRule | null>(null);

  // ─── Query ──────────────────────────────────────────────────────────────────

  const { data, isLoading } = useQuery<ListResponse>({
    queryKey: ['process-block-rules'],
    queryFn: () => apiFetch<ListResponse>('/api/v1/process-rules'),
  });

  const rules = data?.data ?? [];

  // ─── Mutations ──────────────────────────────────────────────────────────────

  type RulePayload = Omit<ProcessBlockRuleForm, 'scope_id'> & { scope_id?: string };

  const createMutation = useMutation({
    mutationFn: (payload: RulePayload) =>
      apiFetch('/api/v1/process-rules', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['process-block-rules'] });
      setShowCreate(false);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: RulePayload }) =>
      apiFetch(`/api/v1/process-rules/${id}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['process-block-rules'] });
      setEditingRule(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/process-rules/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['process-block-rules'] });
      setDeletingRule(null);
    },
  });

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/process-rules/${id}/toggle`, { method: 'PATCH' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['process-block-rules'] });
    },
  });

  // ─── Helpers ────────────────────────────────────────────────────────────────

  const toPayload = (form: ProcessBlockRuleForm): RulePayload => ({
    ...form,
    scope_id: form.scope === 'all' ? undefined : form.scope_id || undefined,
  });

  // ─── Derived ────────────────────────────────────────────────────────────────

  const enabledCount = rules.filter((r) => r.enabled).length;
  const blockCount   = rules.filter((r) => r.action === 'block' || r.action === 'alert_and_block').length;
  const denyCount    = rules.filter((r) => r.rule_type === 'deny').length;

  const editInitial: ProcessBlockRuleForm | null = editingRule
    ? {
        name:         editingRule.name,
        process_name: editingRule.process_name,
        rule_type:    editingRule.rule_type,
        scope:        editingRule.scope,
        scope_id:     editingRule.scope_id ?? '',
        action:       editingRule.action,
        enabled:      editingRule.enabled,
        severity:     editingRule.severity,
      }
    : null;

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f4]">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="max-w-4xl mx-auto px-6 py-8">

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/10 rounded-lg border border-red-500/20">
              <ShieldBan className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-[#e2e8f4]">プロセス実行制御</h1>
              <p className="text-sm text-[#7d92b0] mt-0.5">
                エージェントでのプロセス実行を許可・拒否するルールを設定します
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            新規ルール
          </button>
        </div>

        {/* Warning Banner */}
        <div className="mb-8 flex items-start gap-3 bg-red-500/10 border border-red-500/30 rounded-xl px-5 py-4">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="text-sm text-red-300 space-y-1">
            <p>
              <span className="font-semibold">ブロック</span> または{' '}
              <span className="font-semibold">アラート＋ブロック</span>{' '}
              アクションを設定すると、マッチしたプロセスをエージェントが強制終了します。
            </p>
            <p className="text-xs text-red-400/70">
              ルールを有効にする前に対象プロセスと適用スコープを十分に確認してください。
            </p>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-5 py-4">
            <p className="text-xs text-[#7d92b0] mb-1">総ルール数</p>
            <p className="text-2xl font-bold text-[#e2e8f4]">{rules.length}</p>
          </div>
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-5 py-4">
            <p className="text-xs text-[#7d92b0] mb-1">有効</p>
            <p className="text-2xl font-bold text-green-400">{enabledCount}</p>
          </div>
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-5 py-4">
            <p className="text-xs text-[#7d92b0] mb-1">ブロックルール</p>
            <p className="text-2xl font-bold text-red-400">{blockCount}</p>
          </div>
        </div>

        {/* Info hint */}
        {denyCount > 0 && (
          <p className="text-xs text-[#7d92b0] mb-4">
            拒否ルール{' '}
            <span className="text-[#e2e8f4] font-medium">{denyCount}</span>{' '}
            件が設定されています。エージェントは60秒ごとにルールを更新します。
          </p>
        )}

        {/* Loading */}
        {isLoading && (
          <div className="flex items-center justify-center py-16">
            <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
          </div>
        )}

        {/* Empty State */}
        {!isLoading && rules.length === 0 && (
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl flex flex-col items-center justify-center py-16 text-center">
            <div className="p-3 bg-[#1e2d42] rounded-full mb-4">
              <Terminal className="w-6 h-6 text-[#7d92b0]" />
            </div>
            <p className="text-sm text-[#e2e8f4] font-medium">プロセス制御ルールがありません</p>
            <p className="text-xs text-[#7d92b0] mt-1 max-w-xs">
              「新規ルール」ボタンからプロセス名またはグロブパターンでルールを作成してください
            </p>
            <button
              onClick={() => setShowCreate(true)}
              className="mt-5 flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              最初のルールを作成
            </button>
          </div>
        )}

        {/* Rule List */}
        {!isLoading && rules.length > 0 && (
          <div className="space-y-3">
            {rules.map((rule) => (
              <RuleCard
                key={rule.id}
                rule={rule}
                onEdit={(r) => setEditingRule(r)}
                onDelete={(r) => setDeletingRule(r)}
                onToggle={(id) => toggleMutation.mutate(id)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Create Modal */}
      {showCreate && (
        <RuleFormModal
          title="新規プロセスルールを作成"
          initial={INITIAL_FORM}
          onClose={() => setShowCreate(false)}
          onSubmit={(form) => createMutation.mutate(toPayload(form))}
          isPending={createMutation.isPending}
        />
      )}

      {/* Edit Modal */}
      {editingRule !== null && editInitial !== null && (
        <RuleFormModal
          title={`編集: ${editingRule.name}`}
          initial={editInitial}
          onClose={() => setEditingRule(null)}
          onSubmit={(form) =>
            updateMutation.mutate({ id: editingRule.id, payload: toPayload(form) })
          }
          isPending={updateMutation.isPending}
        />
      )}

      {/* Delete Confirm */}
      {deletingRule !== null && (
        <DeleteConfirmDialog
          ruleName={deletingRule.name}
          onConfirm={() => deleteMutation.mutate(deletingRule.id)}
          onCancel={() => setDeletingRule(null)}
          isPending={deleteMutation.isPending}
        />
      )}
    </div>
  );
}
