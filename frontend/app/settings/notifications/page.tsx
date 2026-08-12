'use client';

import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiFetch } from '@/lib/api';
import {
  Bell,
  Mail,
  Webhook,
  Zap,
  BellOff,
  Loader2,
  CheckCircle2,
  XCircle,
  ToggleLeft,
  ToggleRight,
  ExternalLink,
  CheckCircle,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  CalendarClock,
  FlaskConical,
} from 'lucide-react';
import Link from 'next/link';

// ─── Types ────────────────────────────────────────────────────────────────────

type TabId = 'email' | 'webhook' | 'soar' | 'browser' | 'briefing';

interface NotificationPreferences {
  email_enabled: boolean;
  email_address: string;
  min_severity: string;
  notify_incidents: boolean;
  notify_agent_offline: boolean;
}

interface WebhookTarget {
  id: string;
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
  last_triggered_at?: string;
  last_status?: number;
}

interface SOARConfig {
  id: string;
  name: string;
  type: 'jira' | 'servicenow';
  enabled: boolean;
  min_severity: number;
  auto_create: boolean;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const TABS: { id: TabId; label: string; icon: React.ReactNode }[] = [
  { id: 'email',    label: 'メール通知',         icon: <Mail         className="w-4 h-4" /> },
  { id: 'webhook',  label: 'Webhook',             icon: <Webhook      className="w-4 h-4" /> },
  { id: 'soar',     label: 'SOAR',                icon: <Zap          className="w-4 h-4" /> },
  { id: 'browser',  label: 'ブラウザ通知',        icon: <Bell         className="w-4 h-4" /> },
  { id: 'briefing', label: 'デイリーブリーフィング', icon: <CalendarClock className="w-4 h-4" /> },
];

const SEVERITY_OPTIONS = [
  { value: 'critical', label: '緊急 (Critical)' },
  { value: 'high',     label: '高 (High)' },
  { value: 'medium',   label: '中 (Medium)' },
  { value: 'low',      label: '低 (Low)' },
];

const DEFAULT_PREFS: NotificationPreferences = {
  email_enabled:       false,
  email_address:       '',
  min_severity:        'high',
  notify_incidents:    true,
  notify_agent_offline: true,
};

// ─── Toast ────────────────────────────────────────────────────────────────────

interface ToastState {
  type: 'success' | 'error';
  message: string;
}

function Toast({ toast, onDismiss }: { toast: ToastState; onDismiss: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 3500);
    return () => clearTimeout(t);
  }, [onDismiss]);

  return (
    <div
      className={`fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl border shadow-xl text-sm transition-all ${
        toast.type === 'success'
          ? 'bg-green-900/80 border-green-700/50 text-green-200'
          : 'bg-red-900/80 border-red-700/50 text-red-200'
      }`}
    >
      {toast.type === 'success' ? (
        <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
      ) : (
        <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
      )}
      {toast.message}
    </div>
  );
}

// ─── Email Tab ────────────────────────────────────────────────────────────────

function EmailTab({ onToast }: { onToast: (t: ToastState) => void }) {
  const qc = useQueryClient();

  const { data, isLoading, isError } = useQuery<NotificationPreferences>({
    queryKey: ['notification-prefs'],
    queryFn: async () => {
      try {
        return await apiFetch<NotificationPreferences>('/api/v1/notifications/preferences');
      } catch (e: unknown) {
        // Gracefully handle missing endpoint (404 → return defaults)
        if (e instanceof Error && e.message.includes('404')) return DEFAULT_PREFS;
        throw e;
      }
    },
    retry: false,
  });

  const [form, setForm] = useState<NotificationPreferences>(DEFAULT_PREFS);
  const [isDirty, setIsDirty] = useState(false);

  // Sync fetched data into form state once loaded
  useEffect(() => {
    if (data) {
      setForm(data);
      setIsDirty(false);
    }
  }, [data]);

  const update = <K extends keyof NotificationPreferences>(
    key: K,
    value: NotificationPreferences[K]
  ) => {
    setForm((prev) => ({ ...prev, [key]: value }));
    setIsDirty(true);
  };

  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/notifications/preferences', {
        method: 'PUT',
        body: JSON.stringify(form),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['notification-prefs'] });
      setIsDirty(false);
      onToast({ type: 'success', message: 'メール通知設定を保存しました' });
    },
    onError: (e: unknown) => {
      onToast({
        type: 'error',
        message: e instanceof Error ? e.message : '保存に失敗しました',
      });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <AlertCircle className="w-8 h-8 text-red-400 mb-3" />
        <p className="text-sm text-[#e2e8f4] font-medium">設定の取得に失敗しました</p>
        <p className="text-xs text-[#7d92b0] mt-1">しばらくしてから再試行してください</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Enable toggle */}
      <div className="flex items-center justify-between p-4 bg-[#0d1525] border border-[#1e2d42] rounded-xl">
        <div>
          <p className="text-sm font-medium text-[#e2e8f4]">メール通知を有効にする</p>
          <p className="text-xs text-[#7d92b0] mt-0.5">
            設定した条件でメールアドレスに通知を送信します
          </p>
        </div>
        <button
          type="button"
          onClick={() => update('email_enabled', !form.email_enabled)}
          className="flex-shrink-0 ml-4"
        >
          {form.email_enabled ? (
            <ToggleRight className="w-9 h-9 text-blue-400" />
          ) : (
            <ToggleLeft className="w-9 h-9 text-[#3a4d66]" />
          )}
        </button>
      </div>

      {/* Fields — only fully visible when enabled */}
      <div
        className={`space-y-5 transition-opacity ${
          form.email_enabled ? 'opacity-100' : 'opacity-40 pointer-events-none select-none'
        }`}
      >
        {/* Email address */}
        <div>
          <label className="block text-xs text-[#7d92b0] mb-1.5">
            通知先メールアドレス <span className="text-red-400">*</span>
          </label>
          <input
            type="email"
            value={form.email_address}
            onChange={(e) => update('email_address', e.target.value)}
            placeholder="alerts@example.com"
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-none focus:border-blue-500 transition-colors"
          />
        </div>

        {/* Min severity */}
        <div>
          <label className="block text-xs text-[#7d92b0] mb-1.5">最小重大度</label>
          <select
            value={form.min_severity}
            onChange={(e) => update('min_severity', e.target.value)}
            className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] focus:outline-none focus:border-blue-500 transition-colors"
          >
            {SEVERITY_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <p className="text-xs text-[#7d92b0] mt-1.5">
            選択した重大度以上のイベントのみ通知します
          </p>
        </div>

        {/* Event checkboxes */}
        <div>
          <p className="text-xs text-[#7d92b0] mb-3">通知イベント</p>
          <div className="space-y-3">
            <label className="flex items-center gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={form.notify_incidents}
                onChange={(e) => update('notify_incidents', e.target.checked)}
                className="w-4 h-4 accent-blue-500"
              />
              <div>
                <p className="text-sm text-[#e2e8f4] group-hover:text-white transition-colors">
                  インシデント通知
                </p>
                <p className="text-xs text-[#7d92b0]">
                  インシデントが作成または更新されたときに通知します
                </p>
              </div>
            </label>
            <label className="flex items-center gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={form.notify_agent_offline}
                onChange={(e) => update('notify_agent_offline', e.target.checked)}
                className="w-4 h-4 accent-blue-500"
              />
              <div>
                <p className="text-sm text-[#e2e8f4] group-hover:text-white transition-colors">
                  エージェントオフライン通知
                </p>
                <p className="text-xs text-[#7d92b0]">
                  監視対象のエージェントがオフラインになったときに通知します
                </p>
              </div>
            </label>
          </div>
        </div>
      </div>

      {/* Save button */}
      <div className="flex items-center justify-between pt-2 border-t border-[#1e2d42]">
        {isDirty && (
          <p className="text-xs text-yellow-400 flex items-center gap-1.5">
            <AlertCircle className="w-3.5 h-3.5" />
            未保存の変更があります
          </p>
        )}
        <div className="ml-auto">
          <button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending || !isDirty}
            className="flex items-center gap-2 px-5 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm rounded-lg transition-colors"
          >
            {saveMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <CheckCircle2 className="w-4 h-4" />
            )}
            設定を保存
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Webhook Tab ──────────────────────────────────────────────────────────────

function WebhookTab() {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data, isLoading } = useQuery<{ data: WebhookTarget[] }>({
    queryKey: ['webhooks'],
    queryFn: async () => {
      try {
        return await apiFetch<{ data: WebhookTarget[] }>('/api/v1/webhooks');
      } catch (e: unknown) {
        if (e instanceof Error && e.message.includes('404')) return { data: [] };
        throw e;
      }
    },
    retry: false,
  });

  const targets = data?.data ?? [];
  const enabledCount = targets.filter((t) => t.enabled).length;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Summary stats */}
      {targets.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-1">設定数</p>
            <p className="text-xl font-bold text-[#e2e8f4]">{targets.length}</p>
          </div>
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-1">有効</p>
            <p className="text-xl font-bold text-green-400">{enabledCount}</p>
          </div>
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-1">無効</p>
            <p className="text-xl font-bold text-[#7d92b0]">{targets.length - enabledCount}</p>
          </div>
        </div>
      )}

      {/* Empty state */}
      {targets.length === 0 && (
        <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl flex flex-col items-center justify-center py-14 text-center">
          <div className="p-3 bg-[#1e2d42] rounded-full mb-4">
            <Webhook className="w-6 h-6 text-[#7d92b0]" />
          </div>
          <p className="text-sm text-[#e2e8f4] font-medium">Webhookが設定されていません</p>
          <p className="text-xs text-[#7d92b0] mt-1 max-w-xs">
            Webhook設定ページから外部エンドポイントへの通知を追加できます
          </p>
        </div>
      )}

      {/* Webhook list (read-only summary) */}
      {targets.length > 0 && (
        <div className="space-y-2">
          {targets.map((t) => {
            const isExpanded = expandedId === t.id;
            return (
              <div
                key={t.id}
                className="bg-[#0d1525] border border-[#1e2d42] rounded-xl overflow-hidden"
              >
                <div className="flex items-center justify-between px-5 py-3.5">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="flex-shrink-0">
                      {t.enabled ? (
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                      ) : (
                        <XCircle className="w-4 h-4 text-[#3a4d66]" />
                      )}
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-[#e2e8f4] truncate">{t.name}</p>
                      <p className="text-xs text-[#7d92b0] truncate max-w-xs">{t.url}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                    {t.last_status != null && (
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
                          t.last_status >= 200 && t.last_status < 300
                            ? 'bg-green-500/20 text-green-300 border-green-500/40'
                            : 'bg-red-500/20 text-red-300 border-red-500/40'
                        }`}
                      >
                        HTTP {t.last_status}
                      </span>
                    )}
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : t.id)}
                      className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors p-1"
                    >
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>
                {isExpanded && (
                  <div className="border-t border-[#1e2d42] px-5 py-3 space-y-2">
                    <p className="text-xs text-[#7d92b0]">登録イベント</p>
                    <div className="flex flex-wrap gap-1.5">
                      {t.events.map((ev) => (
                        <span
                          key={ev}
                          className="text-xs px-2 py-0.5 rounded-full border bg-[#1e2d42] border-[#253550] text-[#7d92b0] font-medium"
                        >
                          {ev}
                        </span>
                      ))}
                    </div>
                    {t.last_triggered_at && (
                      <p className="text-xs text-[#3a4d66]">
                        最終配信: {new Date(t.last_triggered_at).toLocaleString('ja-JP')}
                      </p>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Link to webhook settings */}
      <div className="flex items-center justify-between p-4 bg-[#111827] border border-[#1e2d42] rounded-xl">
        <div className="flex items-start gap-3">
          <ExternalLink className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-[#e2e8f4]">Webhook設定ページ</p>
            <p className="text-xs text-[#7d92b0] mt-0.5">
              Webhookの追加・編集・テストはこちらから行えます
            </p>
          </div>
        </div>
        <Link
          href="/settings/webhooks"
          className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#253550] text-[#e2e8f4] text-sm rounded-lg transition-colors flex-shrink-0 ml-4"
        >
          設定へ移動
          <ExternalLink className="w-3.5 h-3.5" />
        </Link>
      </div>
    </div>
  );
}

// ─── SOAR Tab ─────────────────────────────────────────────────────────────────

const SOAR_COLORS: Record<string, string> = {
  jira:       'bg-blue-500/20 text-blue-300 border-blue-500/40',
  servicenow: 'bg-green-500/20 text-green-300 border-green-500/40',
};

const SOAR_LABELS: Record<string, string> = {
  jira:       'Jira',
  servicenow: 'ServiceNow',
};

function SOARTab() {
  const { data, isLoading } = useQuery<{ data: SOARConfig[] }>({
    queryKey: ['soar-configs'],
    queryFn: async () => {
      try {
        return await apiFetch<{ data: SOARConfig[] }>('/api/v1/soar/configs');
      } catch (e: unknown) {
        if (e instanceof Error && e.message.includes('404')) return { data: [] };
        throw e;
      }
    },
    retry: false,
  });

  const configs = data?.data ?? [];
  const activeConfigs = configs.filter((c) => c.enabled);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Summary stats */}
      {configs.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-1">設定数</p>
            <p className="text-xl font-bold text-[#e2e8f4]">{configs.length}</p>
          </div>
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-1">有効</p>
            <p className="text-xl font-bold text-green-400">{activeConfigs.length}</p>
          </div>
          <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl px-4 py-3">
            <p className="text-xs text-[#7d92b0] mb-1">自動起票</p>
            <p className="text-xl font-bold text-purple-400">
              {configs.filter((c) => c.auto_create).length}
            </p>
          </div>
        </div>
      )}

      {/* Empty state */}
      {configs.length === 0 && (
        <div className="bg-[#0d1525] border border-[#1e2d42] rounded-xl flex flex-col items-center justify-center py-14 text-center">
          <div className="p-3 bg-[#1e2d42] rounded-full mb-4">
            <Zap className="w-6 h-6 text-[#7d92b0]" />
          </div>
          <p className="text-sm text-[#e2e8f4] font-medium">SOAR連携が設定されていません</p>
          <p className="text-xs text-[#7d92b0] mt-1 max-w-xs">
            SOAR設定ページから Jira または ServiceNow との連携を追加できます
          </p>
        </div>
      )}

      {/* Active configs summary */}
      {configs.length > 0 && (
        <div className="space-y-2">
          {configs.map((c) => (
            <div
              key={c.id}
              className="flex items-center justify-between px-5 py-3.5 bg-[#0d1525] border border-[#1e2d42] rounded-xl"
            >
              <div className="flex items-center gap-3 min-w-0">
                <div className="flex-shrink-0">
                  {c.enabled ? (
                    <CheckCircle2 className="w-4 h-4 text-green-400" />
                  ) : (
                    <XCircle className="w-4 h-4 text-[#3a4d66]" />
                  )}
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium text-[#e2e8f4] truncate">
                      {c.name}
                    </span>
                    <span
                      className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
                        SOAR_COLORS[c.type] ?? 'bg-[#1e2d42] text-[#7d92b0] border-[#253550]'
                      }`}
                    >
                      {SOAR_LABELS[c.type] ?? c.type}
                    </span>
                    {c.auto_create && (
                      <span className="text-xs px-2 py-0.5 rounded-full border font-medium bg-purple-500/20 text-purple-300 border-purple-500/40 flex items-center gap-1">
                        <Zap className="w-3 h-3" />
                        自動起票
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-[#7d92b0] mt-0.5">
                    最小重大度: {c.min_severity} &nbsp;·&nbsp;
                    {c.enabled ? '有効' : '無効'}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Link to SOAR settings */}
      <div className="flex items-center justify-between p-4 bg-[#111827] border border-[#1e2d42] rounded-xl">
        <div className="flex items-start gap-3">
          <ExternalLink className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-[#e2e8f4]">SOAR連携設定ページ</p>
            <p className="text-xs text-[#7d92b0] mt-0.5">
              連携の追加・編集・テストはSOAR設定ページから行えます
            </p>
          </div>
        </div>
        <Link
          href="/settings/soar"
          className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#253550] text-[#e2e8f4] text-sm rounded-lg transition-colors flex-shrink-0 ml-4"
        >
          設定へ移動
          <ExternalLink className="w-3.5 h-3.5" />
        </Link>
      </div>
    </div>
  );
}

// ─── Browser Tab ──────────────────────────────────────────────────────────────

function BrowserTab() {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center space-y-4">
      <div className="p-4 bg-[#1e2d42] rounded-full">
        <BellOff className="w-8 h-8 text-[#7d92b0]" />
      </div>
      <div>
        <p className="text-sm font-medium text-[#e2e8f4]">ブラウザ通知は近日対応予定です</p>
        <p className="text-xs text-[#7d92b0] mt-1.5 max-w-xs">
          ブラウザのプッシュ通知機能は現在開発中です。対応後にここで設定できるようになります。
        </p>
      </div>
      <span className="text-xs px-3 py-1 rounded-full border bg-yellow-500/10 text-yellow-300 border-yellow-500/30 font-medium">
        Coming Soon
      </span>
    </div>
  );
}

// ─── Briefing Tab ─────────────────────────────────────────────────────────────

interface BriefingStatus {
  slack_enabled: boolean;
  webhook_enabled: boolean;
  email_enabled: boolean;
  email_to: string;
  smtp_host: string;
  hour: number;
}

interface BriefingTestResult {
  message: string;
  urgent_alerts: number;
  open_incidents: number;
  new_alerts_today: number;
  slack_enabled: boolean;
  email_enabled: boolean;
}

function BriefingTab() {
  const [testResult, setTestResult] = useState<BriefingTestResult | null>(null);

  const { data: status, isLoading } = useQuery<BriefingStatus>({
    queryKey: ['briefing-status'],
    queryFn: () => apiFetch('/api/v1/settings/briefing/status'),
    refetchInterval: false,
  });

  const testMutation = useMutation({
    mutationFn: () => apiFetch<BriefingTestResult>('/api/v1/settings/briefing/test', { method: 'POST' }),
    onSuccess: (data) => {
      setTestResult(data);
      setTimeout(() => setTestResult(null), 10000);
    },
  });

  const StatusBadge = ({ enabled, label }: { enabled: boolean; label: string }) => (
    <div className="flex items-center justify-between py-3 border-b border-[#1e2d42] last:border-0">
      <span className="text-sm text-[#e2e8f4]">{label}</span>
      <span className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full font-medium ${
        enabled
          ? 'bg-green-900/30 text-green-400 border border-green-700/40'
          : 'bg-[#1e2d42] text-[#3d5068] border border-[#1e2d42]'
      }`}>
        {enabled ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
        {enabled ? '有効' : '未設定'}
      </span>
    </div>
  );

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-sm font-semibold text-[#e2e8f4] mb-1">配信状態</h3>
        <p className="text-xs text-[#7d92b0] mb-4">
          毎朝 {status?.hour ?? 8}:00 に前日のセキュリティサマリーを自動送信します。
          配信先はサーバーの環境変数で設定します。
        </p>
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] px-4">
          {isLoading ? (
            <p className="py-4 text-sm text-[#3d5068]">確認中...</p>
          ) : (
            <>
              <StatusBadge enabled={status?.slack_enabled ?? false} label="Slack Incoming Webhook" />
              <StatusBadge enabled={status?.email_enabled ?? false}
                label={`メール配信${status?.email_to ? ` (${status.email_to})` : ''}`} />
              <StatusBadge enabled={status?.webhook_enabled ?? false} label="汎用 Webhook" />
            </>
          )}
        </div>
      </div>

      {/* 設定方法 */}
      <div>
        <h3 className="text-sm font-semibold text-[#e2e8f4] mb-2">設定方法（環境変数）</h3>
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4 space-y-3">
          {[
            { var: 'BRIEFING_SLACK_WEBHOOK_URL', desc: 'Slack Incoming Webhook URL' },
            { var: 'BRIEFING_EMAIL_TO', desc: '送信先メールアドレス（カンマ区切りで複数可）' },
            { var: 'BRIEFING_SMTP_HOST', desc: 'SMTPサーバー（例: smtp.gmail.com）' },
            { var: 'BRIEFING_SMTP_PORT', desc: 'SMTPポート（デフォルト: 587）' },
            { var: 'BRIEFING_SMTP_USER', desc: 'SMTP認証ユーザー' },
            { var: 'BRIEFING_SMTP_PASS', desc: 'SMTP認証パスワード（Gmailはアプリパスワード）' },
            { var: 'BRIEFING_EMAIL_FROM', desc: '送信元メールアドレス' },
            { var: 'BRIEFING_WEBHOOK_URL', desc: '汎用Webhook URL（JSON POSTで配信）' },
          ].map(({ var: v, desc }) => (
            <div key={v}>
              <code className="text-xs text-[#e8002d] font-mono">{v}</code>
              <p className="text-xs text-[#3d5068] mt-0.5">{desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* テスト送信 */}
      <div>
        <h3 className="text-sm font-semibold text-[#e2e8f4] mb-2">テスト確認</h3>
        <p className="text-xs text-[#7d92b0] mb-3">
          現在のデータでブリーフィング内容を確認できます（外部への実送信はしません）。
        </p>
        <button
          onClick={() => testMutation.mutate()}
          disabled={testMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-[#161f33] hover:bg-[#1d2f4a]
                     border border-[#1e2d42] text-sm text-[#e2e8f4] rounded-lg transition-colors
                     disabled:opacity-50"
        >
          <FlaskConical className={`w-4 h-4 ${testMutation.isPending ? 'animate-pulse' : ''}`} />
          {testMutation.isPending ? '確認中...' : 'ブリーフィング内容を確認'}
        </button>
        {testResult && (
          <div className="mt-3 bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4 space-y-2 text-sm">
            <p className="text-green-400 font-medium">{testResult.message}</p>
            <div className="grid grid-cols-3 gap-3 pt-2">
              {[
                { label: '新規アラート', value: testResult.new_alerts_today },
                { label: '緊急アラート', value: testResult.urgent_alerts },
                { label: '未処理インシデント', value: testResult.open_incidents },
              ].map(({ label, value }) => (
                <div key={label} className="text-center bg-[#161f33] rounded-lg py-2">
                  <p className="text-xl font-bold text-white">{value}</p>
                  <p className="text-xs text-[#3d5068] mt-0.5">{label}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function NotificationsPage() {
  const [activeTab, setActiveTab] = useState<TabId>('email');
  const [toast, setToast] = useState<ToastState | null>(null);

  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f4]">
      <div className="max-w-3xl mx-auto px-6 py-8">

        {/* Header */}
        <div className="flex items-center gap-3 mb-8">
          <div className="p-2 bg-blue-500/10 rounded-lg border border-blue-500/20">
            <Bell className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-[#e2e8f4]">通知設定</h1>
            <p className="text-sm text-[#7d92b0] mt-0.5">
              メール・Webhook・SOAR など全ての通知チャンネルを一元管理します
            </p>
          </div>
        </div>

        {/* Tab container */}
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] overflow-hidden">

          {/* Tab header */}
          <div className="flex border-b border-[#1e2d42] overflow-x-auto">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-5 py-3.5 text-sm font-medium transition-colors border-b-2 -mb-px flex-shrink-0 ${
                  activeTab === tab.id
                    ? 'text-white border-blue-500 bg-blue-500/5'
                    : 'text-[#7d92b0] border-transparent hover:text-white hover:bg-[#161f33]'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="p-6">
            {activeTab === 'email'    && <EmailTab   onToast={setToast} />}
            {activeTab === 'webhook'  && <WebhookTab />}
            {activeTab === 'soar'     && <SOARTab />}
            {activeTab === 'browser'  && <BrowserTab />}
            {activeTab === 'briefing' && <BriefingTab />}
          </div>
        </div>
      </div>

      {/* Toast notification */}
      {toast && (
        <Toast toast={toast} onDismiss={() => setToast(null)} />
      )}
    </div>
  );
}
