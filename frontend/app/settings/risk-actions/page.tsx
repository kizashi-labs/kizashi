'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiFetch, apiFetchList } from '@/lib/api';
import {
  Plus,
  Trash2,
  X,
  Loader2,
  ToggleLeft,
  ToggleRight,
  AlertTriangle,
  Zap,
  ShieldAlert,
  BellRing,
  Pencil,
} from 'lucide-react';

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

type ActionType = 'isolate' | 'alert_only';

interface RiskActionRule {
  id: string;
  name: string;
  threshold: number;
  action: ActionType;
  enabled: boolean;
  created_at: string;
}

interface RiskActionRuleForm {
  name: string;
  threshold: number;
  action: ActionType;
  enabled: boolean;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const INITIAL_FORM: RiskActionRuleForm = {
  name: '',
  threshold: 75,
  action: 'alert_only',
  enabled: true,
};

const ACTION_STYLES: Record<ActionType, string> = {
  isolate:    'bg-red-500/20 text-red-300 border-red-500/40',
  alert_only: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
};

const ACTION_LABELS: Record<ActionType, string> = {
  isolate:    '隔離',
  alert_only: 'アラートのみ',
};

// ─── Threshold Gauge Badge ────────────────────────────────────────────────────

function ThresholdBadge({ value }: { value: number }) {
  const color =
    value >= 80 ? 'bg-red-500/20 text-red-300 border-red-500/40' :
    value >= 50 ? 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40' :
                  'bg-green-500/20 text-green-300 border-green-500/40';

  return (
    <span className={`text-xs px-2.5 py-0.5 rounded-full border font-mono font-medium ${color}`}>
      ≥ {value}
    </span>
  );
}

// ─── Action Badge ─────────────────────────────────────────────────────────────

function ActionBadge({ action }: { action: ActionType }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium flex items-center gap-1 w-fit ${ACTION_STYLES[action]}`}>
      {action === 'isolate' ? (
        <ShieldAlert className="w-3 h-3" />
      ) : (
        <BellRing className="w-3 h-3" />
      )}
      {ACTION_LABELS[action]}
    </span>
  );
}

// ─── Slider Field ─────────────────────────────────────────────────────────────

function SliderField({
  value,
  onChange,
}: {
  value: number;
  onChange: (v: number) => void;
}) {
  const trackColor =
    value >= 80 ? '#ef4444' :
    value >= 50 ? '#eab308' :
                  '#22c55e';

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-xs text-[#7d92b0]">閾値スコア</label>
        <span
          className="text-sm font-mono font-bold tabular-nums"
          style={{ color: trackColor }}
        >
          {value}
        </span>
      </div>
      <input
        type="range"
        min={1}
        max={100}
        step={1}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full h-1.5 bg-[#1e2d42] rounded-full appearance-none cursor-pointer [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-[#1a6bff] [&::-webkit-slider-thumb]:cursor-pointer"
      />
      <div className="flex justify-between text-[#3a4d66] text-xs">
        <span>1</span>
        <span>100</span>
      </div>
    </div>
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
  initial: RiskActionRuleForm;
  onClose: () => void;
  onSubmit: (form: RiskActionRuleForm) => void;
  isPending: boolean;
}) {
  const [form, setForm] = useState<RiskActionRuleForm>({ ...initial });
  const [error, setError] = useState('');

  const handleSubmit = () => {
    if (!form.name.trim()) {
      setError('ルール名を入力してください');
      return;
    }
    setError('');
    onSubmit(form);
  };

  const set = <K extends keyof RiskActionRuleForm>(k: K, v: RiskActionRuleForm[K]) =>
    setForm((f) => ({ ...f, [k]: v }));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111827] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md mx-4 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-sm font-semibold text-[#e2e8f4] flex items-center gap-2">
            <Zap className="w-4 h-4 text-yellow-400" />
            {title}
          </h2>
          <button
            onClick={onClose}
            className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-5">
          {/* Name */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">
              ルール名 <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => set('name', e.target.value)}
              placeholder="高リスク自動隔離"
              autoComplete="off"
              className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#3a4d66] focus:outline-hidden focus:border-blue-500"
            />
          </div>

          {/* Threshold Slider */}
          <div className="bg-[#080c14] border border-[#1e2d42] rounded-lg p-4">
            <SliderField value={form.threshold} onChange={(v) => set('threshold', v)} />
            <p className="text-xs text-[#7d92b0] mt-3">
              リスクスコアが <span className="text-[#e2e8f4] font-mono">{form.threshold}</span> 以上のエンドポイントに対してアクションを実行します
            </p>
          </div>

          {/* Action Selector */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-2">アクション</label>
            <div className="grid grid-cols-2 gap-3">
              {(['alert_only', 'isolate'] as ActionType[]).map((a) => (
                <button
                  key={a}
                  type="button"
                  onClick={() => set('action', a)}
                  className={`flex items-center gap-2 px-3 py-3 rounded-lg border text-sm font-medium transition-colors
                    ${form.action === a
                      ? a === 'isolate'
                        ? 'bg-red-500/20 border-red-500/50 text-red-300'
                        : 'bg-yellow-500/20 border-yellow-500/50 text-yellow-300'
                      : 'bg-[#0d1525] border-[#1e2d42] text-[#7d92b0] hover:border-[#2a3d5a]'
                    }`}
                >
                  {a === 'isolate' ? (
                    <ShieldAlert className="w-4 h-4 shrink-0" />
                  ) : (
                    <BellRing className="w-4 h-4 shrink-0" />
                  )}
                  {ACTION_LABELS[a]}
                </button>
              ))}
            </div>
            {form.action === 'isolate' && (
              <p className="text-xs text-red-400 mt-2 flex items-start gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                隔離を選択すると条件一致時にエンドポイントが即座にネットワークから切断されます
              </p>
            )}
          </div>

          {/* Enable Toggle */}
          <div className="flex items-center justify-between">
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
  rule: RiskActionRule;
  onEdit: (rule: RiskActionRule) => void;
  onDelete: (rule: RiskActionRule) => void;
  onToggle: (id: string) => void;
}) {
  return (
    <div
      className={`bg-[#0d1525] border rounded-xl px-5 py-4 transition-colors
        ${rule.action === 'isolate'
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
          <div className="flex items-center gap-2 flex-wrap">
            <ThresholdBadge value={rule.threshold} />
            <ActionBadge action={rule.action} />
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
          {/* Toggle */}
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
          {/* Edit */}
          <button
            onClick={() => onEdit(rule)}
            title="編集"
            className="p-1.5 text-[#7d92b0] hover:text-blue-400 transition-colors rounded-lg hover:bg-blue-900/20"
          >
            <Pencil className="w-4 h-4" />
          </button>
          {/* Delete */}
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

export default function RiskActionsPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editingRule, setEditingRule] = useState<RiskActionRule | null>(null);
  const [deletingRule, setDeletingRule] = useState<RiskActionRule | null>(null);

  // ─── Query ───────────────────────────────────────────────────────────────────

  const { data, isLoading } = useQuery<RiskActionRule[]>({
    queryKey: ['risk-action-rules'],
    queryFn: () => apiFetchList<RiskActionRule>('/api/v1/risk-actions'),
  });

  const rules = data ?? [];

  // ─── Mutations ───────────────────────────────────────────────────────────────

  const createMutation = useMutation({
    mutationFn: (payload: RiskActionRuleForm) =>
      apiFetch('/api/v1/risk-actions', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['risk-action-rules'] });
      setShowCreate(false);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: RiskActionRuleForm }) =>
      apiFetch(`/api/v1/risk-actions/${id}`, {
        method: 'PUT',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['risk-action-rules'] });
      setEditingRule(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/risk-actions/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['risk-action-rules'] });
      setDeletingRule(null);
    },
  });

  const toggleMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/risk-actions/${id}/toggle`, { method: 'PATCH' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['risk-action-rules'] });
    },
  });

  // ─── Derived ─────────────────────────────────────────────────────────────────

  const enabledCount  = rules.filter((r) => r.enabled).length;
  const isolateCount  = rules.filter((r) => r.action === 'isolate').length;

  const editInitial: RiskActionRuleForm | null = editingRule
    ? {
        name:      editingRule.name,
        threshold: editingRule.threshold,
        action:    editingRule.action,
        enabled:   editingRule.enabled,
      }
    : null;

  // ─── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f4]">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="max-w-4xl mx-auto px-6 py-8">

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-500/10 rounded-lg border border-red-500/20">
              <Zap className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-[#e2e8f4]">リスクスコア自動アクション</h1>
              <p className="text-sm text-[#7d92b0] mt-0.5">
                リスクスコアの閾値に応じた自動アクションルールを設定します
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
          <p className="text-sm text-red-300">
            自動隔離は有効にすると即座にエンドポイントをネットワークから切断します。
            ルールを有効にする前に対象範囲を十分に確認してください。
          </p>
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
            <p className="text-xs text-[#7d92b0] mb-1">自動隔離ルール</p>
            <p className="text-2xl font-bold text-red-400">{isolateCount}</p>
          </div>
        </div>

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
              <Zap className="w-6 h-6 text-[#7d92b0]" />
            </div>
            <p className="text-sm text-[#e2e8f4] font-medium">自動アクションルールがありません</p>
            <p className="text-xs text-[#7d92b0] mt-1 max-w-xs">
              「新規ルール」ボタンからリスクスコアに基づく自動アクションルールを作成してください
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
          title="新規ルールを作成"
          initial={INITIAL_FORM}
          onClose={() => setShowCreate(false)}
          onSubmit={(form) => createMutation.mutate(form)}
          isPending={createMutation.isPending}
        />
      )}

      {/* Edit Modal */}
      {editingRule !== null && editInitial !== null && (
        <RuleFormModal
          title={`編集: ${editingRule.name}`}
          initial={editInitial}
          onClose={() => setEditingRule(null)}
          onSubmit={(form) => updateMutation.mutate({ id: editingRule.id, payload: form })}
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
