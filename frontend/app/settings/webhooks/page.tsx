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
  X,
  ToggleLeft,
  ToggleRight,
  ChevronDown,
  ChevronUp,
  Webhook,
  Send,
  Shield,
} from 'lucide-react';

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

interface WebhookTarget {
  id: string;
  name: string;
  url: string;
  secret: string;
  events: string[];
  enabled: boolean;
  last_triggered_at?: string;
  last_status?: number;
  created_at: string;
  updated_at: string;
}

interface WebhookForm {
  name: string;
  url: string;
  secret: string;
  events: string[];
  enabled: boolean;
}

// ─── Constants ────────────────────────────────────────────────────────────────

// **ここに出す値は、サーバが実際に送るものだけです。**
//
// `incident.created` と `incident.updated` を出していましたが、送る経路が
// ありません —— webhook の通知器が購読しているのは `alerts.>` と
// `agent.events.>` だけです。選んだ担当者の webhook は**永久に鳴らず**、
// 「インシデントが起きていない」と見分けが付きませんでした。
//
// この一覧は `server/internal/notification/webhook_events.go` の
// `EmittedWebhookEvents` と揃っている必要があり、
// `TestTheConsoleOffersOnlyEventsThatAreSent` が確かめます。
// **インシデントの webhook が要るなら、まず送る側を作る話です。**
const ALL_EVENTS = [
  { value: 'alert.critical',    label: 'アラート: 緊急',          color: 'text-red-400' },
  { value: 'alert.high',        label: 'アラート: 高',            color: 'text-orange-400' },
  { value: 'alert.any',         label: 'アラート: 全て',          color: 'text-yellow-400' },
  { value: 'agent.offline',     label: 'エージェント: オフライン', color: 'text-purple-400' },
];

const INITIAL_FORM: WebhookForm = {
  name:    '',
  url:     '',
  secret:  '',
  events:  ['alert.critical'],
  enabled: true,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function statusBadge(status?: number) {
  if (status == null) return null;
  const ok = status >= 200 && status < 300;
  return (
    <span
      className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
        ok
          ? 'bg-green-500/20 text-green-300 border-green-500/40'
          : 'bg-red-500/20 text-red-300 border-red-500/40'
      }`}
    >
      HTTP {status}
    </span>
  );
}

// ─── Event Checkboxes ─────────────────────────────────────────────────────────

function EventCheckboxes({
  selected,
  onChange,
}: {
  selected: string[];
  onChange: (events: string[]) => void;
}) {
  const toggle = (val: string) => {
    if (selected.includes(val)) {
      onChange(selected.filter((e) => e !== val));
    } else {
      onChange([...selected, val]);
    }
  };

  return (
    <div className="grid grid-cols-2 gap-2">
      {ALL_EVENTS.map((ev) => (
        <label
          key={ev.value}
          className="flex items-center gap-2 cursor-pointer group"
        >
          <input
            type="checkbox"
            checked={selected.includes(ev.value)}
            onChange={() => toggle(ev.value)}
            className="w-3.5 h-3.5 accent-blue-500"
          />
          <span className={`text-xs ${ev.color}`}>{ev.label}</span>
        </label>
      ))}
    </div>
  );
}

// ─── Add / Edit Modal ─────────────────────────────────────────────────────────

function WebhookModal({
  initial,
  onClose,
  onSaved,
}: {
  initial?: WebhookTarget;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isEdit = !!initial;
  const [form, setForm] = useState<WebhookForm>(
    initial
      ? {
          name:    initial.name,
          url:     initial.url,
          secret:  '',
          events:  initial.events,
          enabled: initial.enabled,
        }
      : { ...INITIAL_FORM }
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async () => {
    if (!form.name.trim()) { setError('名前を入力してください'); return; }
    if (!form.url.trim())  { setError('URLを入力してください'); return; }
    if (form.events.length === 0) { setError('イベントを1つ以上選択してください'); return; }
    setError('');
    setSubmitting(true);
    try {
      if (isEdit) {
        await apiFetch(`/api/v1/webhooks/${initial!.id}`, {
          method: 'PUT',
          body: JSON.stringify(form),
        });
      } else {
        await apiFetch('/api/v1/webhooks', {
          method: 'POST',
          body: JSON.stringify(form),
        });
      }
      onSaved();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : '保存に失敗しました');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#111827] border border-blue-500/30 rounded-xl p-6 w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-sm font-semibold text-[#e2e8f4]">
            {isEdit ? 'Webhookを編集' : '新しいWebhookを追加'}
          </h2>
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
              placeholder="本番アラートWebhook"
              className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-hidden focus:border-blue-500"
            />
          </div>

          {/* URL */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">
              エンドポイントURL <span className="text-red-400">*</span>
            </label>
            <input
              type="url"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
              placeholder="https://hooks.example.com/endpoint"
              className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-hidden focus:border-blue-500"
            />
          </div>

          {/* シークレット */}
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">
              署名シークレット
              <span className="text-[#3a4d66] ml-1">(省略可 — HMAC-SHA256)</span>
            </label>
            <input
              type="password"
              value={form.secret}
              onChange={(e) => setForm({ ...form, secret: e.target.value })}
              placeholder={isEdit ? '変更する場合のみ入力' : 'シークレットキー'}
              autoComplete="off"
              className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-hidden focus:border-blue-500"
            />
          </div>

          {/* イベント */}
          <div className="pt-1 border-t border-[#1e2d42]">
            <p className="text-xs text-[#7d92b0] mb-3">
              トリガーイベント <span className="text-red-400">*</span>
            </p>
            <EventCheckboxes
              selected={form.events}
              onChange={(events) => setForm({ ...form, events })}
            />
          </div>

          {/* 有効化 */}
          <div className="flex items-center justify-between pt-1 border-t border-[#1e2d42]">
            <div>
              <p className="text-sm text-[#e2e8f4]">有効化</p>
              <p className="text-xs text-[#7d92b0] mt-0.5">このWebhookを有効にします</p>
            </div>
            <button
              type="button"
              onClick={() => setForm({ ...form, enabled: !form.enabled })}
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
            {isEdit ? '更新' : '追加'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Webhook Card ─────────────────────────────────────────────────────────────

function WebhookCard({
  target,
  onDelete,
  onToggle,
  onTest,
  onEdit,
}: {
  target: WebhookTarget;
  onDelete: (id: string) => void;
  onToggle: (id: string, enabled: boolean) => void;
  onTest: (id: string) => Promise<{ success: boolean; status_code?: number; error?: string }>;
  onEdit: (target: WebhookTarget) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await onTest(target.id);
      setTestResult({
        success: res.success,
        message: res.success
          ? `テスト成功 (HTTP ${res.status_code})`
          : (res.error ?? 'テスト失敗'),
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
          <div className="shrink-0">
            {target.enabled ? (
              <CheckCircle2 className="w-4 h-4 text-green-400" />
            ) : (
              <XCircle className="w-4 h-4 text-[#3a4d66]" />
            )}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-medium text-[#e2e8f4] truncate">{target.name}</span>
              {statusBadge(target.last_status)}
            </div>
            <p className="text-xs text-[#7d92b0] mt-0.5 truncate max-w-xs">{target.url}</p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => onToggle(target.id, !target.enabled)}
            title={target.enabled ? '無効化' : '有効化'}
            className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors p-1"
          >
            {target.enabled ? (
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
            onClick={() => onEdit(target)}
            className="text-[#7d92b0] hover:text-blue-400 transition-colors p-1"
            title="編集"
          >
            <Shield className="w-4 h-4" />
          </button>
          <button
            onClick={() => onDelete(target.id)}
            className="text-[#7d92b0] hover:text-red-400 transition-colors p-1"
            title="削除"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="border-t border-[#1e2d42] px-5 py-4 space-y-4">
          {/* Events */}
          <div>
            <p className="text-xs text-[#7d92b0] mb-2">登録イベント</p>
            <div className="flex flex-wrap gap-2">
              {target.events.map((ev) => {
                const def = ALL_EVENTS.find((e) => e.value === ev);
                return (
                  <span
                    key={ev}
                    className={`text-xs px-2 py-0.5 rounded-full border font-medium bg-[#1e2d42] border-[#253550] ${def?.color ?? 'text-[#7d92b0]'}`}
                  >
                    {def?.label ?? ev}
                  </span>
                );
              })}
            </div>
          </div>

          {/* Test */}
          <div className="flex items-center gap-3 pt-2 border-t border-[#1e2d42]">
            <button
              onClick={handleTest}
              disabled={testing}
              className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#253550] disabled:opacity-50 text-[#e2e8f4] text-sm rounded-lg transition-colors"
            >
              {testing ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              テスト配信
            </button>
            {testResult && (
              <div
                className={`flex items-center gap-2 text-sm ${
                  testResult.success ? 'text-green-400' : 'text-red-400'
                }`}
              >
                {testResult.success ? (
                  <CheckCircle2 className="w-4 h-4" />
                ) : (
                  <XCircle className="w-4 h-4" />
                )}
                {testResult.message}
              </div>
            )}
          </div>

          {/* Timestamps */}
          <p className="text-xs text-[#3a4d66]">
            作成: {new Date(target.created_at).toLocaleString('ja-JP')}
            {target.last_triggered_at && (
              <> &nbsp;·&nbsp; 最終配信: {new Date(target.last_triggered_at).toLocaleString('ja-JP')}</>
            )}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function WebhooksPage() {
  const qc = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [editTarget, setEditTarget] = useState<WebhookTarget | null>(null);

  const { data, isLoading } = useQuery<{ data: WebhookTarget[] }>({
    queryKey: ['webhooks'],
    queryFn: () => apiFetch<{ data: WebhookTarget[] }>('/api/v1/webhooks'),
  });

  const targets = data?.data ?? [];

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/webhooks/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiFetch(`/api/v1/webhooks/${id}/toggle`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  });

  const handleTest = async (
    id: string
  ): Promise<{ success: boolean; status_code?: number; error?: string }> => {
    try {
      const res = await apiFetch<{ success: boolean; status_code?: number; error?: string }>(
        `/api/v1/webhooks/${id}/test`,
        { method: 'POST' }
      );
      return res;
    } catch (e: unknown) {
      return { success: false, error: e instanceof Error ? e.message : 'テスト失敗' };
    }
  };

  const enabledCount = targets.filter((t) => t.enabled).length;

  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f4]">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      <div className="max-w-4xl mx-auto px-6 py-8">

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20">
              <Webhook className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-[#e2e8f4]">Webhook通知</h1>
              <p className="text-sm text-[#7d92b0] mt-0.5">
                アラートやインシデント発生時に外部エンドポイントへHTTP POSTで通知します
              </p>
            </div>
          </div>
          <button
            onClick={() => { setEditTarget(null); setShowModal(true); }}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Webhookを追加
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-5 py-4">
            <p className="text-xs text-[#7d92b0] mb-1">設定数</p>
            <p className="text-2xl font-bold text-[#e2e8f4]">{targets.length}</p>
          </div>
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-5 py-4">
            <p className="text-xs text-[#7d92b0] mb-1">有効</p>
            <p className="text-2xl font-bold text-green-400">{enabledCount}</p>
          </div>
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-5 py-4">
            <p className="text-xs text-[#7d92b0] mb-1">無効</p>
            <p className="text-2xl font-bold text-[#7d92b0]">{targets.length - enabledCount}</p>
          </div>
        </div>

        {/* Loading */}
        {isLoading && (
          <div className="flex items-center justify-center py-16">
            <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
          </div>
        )}

        {/* Empty State */}
        {!isLoading && targets.length === 0 && (
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl flex flex-col items-center justify-center py-16 text-center">
            <div className="p-3 bg-[#1e2d42] rounded-full mb-4">
              <Webhook className="w-6 h-6 text-[#7d92b0]" />
            </div>
            <p className="text-sm text-[#e2e8f4] font-medium">Webhookが設定されていません</p>
            <p className="text-xs text-[#7d92b0] mt-1 max-w-xs">
              「Webhookを追加」ボタンから外部エンドポイントへの通知を設定してください
            </p>
            <button
              onClick={() => { setEditTarget(null); setShowModal(true); }}
              className="mt-5 flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              最初のWebhookを追加
            </button>
          </div>
        )}

        {/* Webhook List */}
        {targets.length > 0 && (
          <div className="space-y-3">
            {targets.map((t) => (
              <WebhookCard
                key={t.id}
                target={t}
                onDelete={(id) => deleteMutation.mutate(id)}
                onToggle={(id, enabled) => toggleMutation.mutate({ id, enabled })}
                onTest={handleTest}
                onEdit={(target) => { setEditTarget(target); setShowModal(true); }}
              />
            ))}
          </div>
        )}

        {/* Signature Info */}
        {targets.length > 0 && (
          <div className="mt-8 bg-[#111827] border border-[#1e2d42] rounded-xl px-5 py-4">
            <div className="flex items-start gap-3">
              <Shield className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-[#e2e8f4]">ペイロード署名</p>
                <p className="text-xs text-[#7d92b0] mt-1">
                  シークレットが設定されている場合、リクエストには
                  <code className="mx-1 px-1 bg-[#1e2d42] rounded-sm text-blue-300 text-xs">X-Hub-Signature-256</code>
                  ヘッダーが付与されます。値は
                  <code className="mx-1 px-1 bg-[#1e2d42] rounded-sm text-blue-300 text-xs">sha256=&lt;HMAC-SHA256&gt;</code>
                  形式です。
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Modal */}
      {showModal && (
        <WebhookModal
          initial={editTarget ?? undefined}
          onClose={() => { setShowModal(false); setEditTarget(null); }}
          onSaved={() => {
            setShowModal(false);
            setEditTarget(null);
            qc.invalidateQueries({ queryKey: ['webhooks'] });
          }}
        />
      )}
    </div>
  );
}
