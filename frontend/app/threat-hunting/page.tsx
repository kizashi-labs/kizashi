'use client';

import { useState, useMemo, useCallback, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiFetch } from '@/lib/api';
import { useCanWrite } from '@/lib/auth';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
} from 'recharts';
import {
  Search,
  Save,
  Trash2,
  Play,
  BookOpen,
  Clock,
  BarChart2,
  Zap,
  ChevronDown,
  ChevronUp,
  X,
  Database,
  Cpu,
  Globe,
  Shield,
  AlertTriangle,
  Download,
  Table2,
  TrendingUp,
  Loader2,
  SlidersHorizontal,
  Terminal,
  RefreshCw,
  Layers,
  Plus,
  ArrowDown,
  CalendarClock,
  Bell,
  BookMarked,
  ChevronRight,
  Filter,
  GitMerge,
  BarChart,
  TriangleAlert,
  Wrench,
  Copy,
  Check,
  Share2,
} from 'lucide-react';

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

interface HuntParams {
  query?: string;
  eventType?: string;
  hostname?: string;
  processName?: string;
  username?: string;
  startTime?: string;
  endTime?: string;
  timeRange?: string;
}

interface SavedHunt {
  id: string;
  name: string;
  description: string;
  params: HuntParams;
  created_by: string;
  created_at: string;
  last_run?: string;
  run_count: number;
}

interface EventRecord {
  id: string;
  event_type: string;
  hostname: string;
  process_name?: string;
  username?: string;
  timestamp: string;
  severity?: number;
  details?: Record<string, unknown>;
  [key: string]: unknown;
}

interface HuntResult {
  data: EventRecord[];
  total: number;
}

type ViewMode = 'table' | 'timeline';

type MainTab = 'hunt' | 'builder';

// ─── Hunt Builder Types ────────────────────────────────────────────────────────

type StepType = 'filter' | 'correlate' | 'aggregate' | 'alert';

interface BuilderStep {
  id: string
  type: StepType
  query: string
  condition: string
  label: string
}

interface PlaybookPayload {
  name: string
  description: string
  steps: BuilderStep[]
}

// ─── Schedule Types ────────────────────────────────────────────────────────────

type ScheduleFrequency = 'hourly' | 'daily' | 'weekly';

interface SchedulePayload {
  name: string
  frequency: ScheduleFrequency
  hunt_steps: BuilderStep[]
  notify_on_findings: boolean
  notification_email?: string
}

// ─── Constants ────────────────────────────────────────────────────────────────

const QUERY_TYPE_OPTIONS = [
  { value: '', label: 'すべてのタイプ', icon: null },
  { value: 'process_creation', label: 'Process', icon: <Cpu className="w-3.5 h-3.5" /> },
  { value: 'network_connection', label: 'Network', icon: <Globe className="w-3.5 h-3.5" /> },
  { value: 'file_event', label: 'File', icon: <Database className="w-3.5 h-3.5" /> },
  { value: 'authentication', label: 'Authentication', icon: <Shield className="w-3.5 h-3.5" /> },
  { value: 'dns', label: 'DNS', icon: <Globe className="w-3.5 h-3.5 text-cyan-400" /> },
  { value: 'registry_set', label: 'Registry', icon: <SlidersHorizontal className="w-3.5 h-3.5" /> },
  { value: 'image_load', label: 'DLL Load', icon: <Zap className="w-3.5 h-3.5" /> },
];

const TIME_RANGE_OPTIONS = [
  { value: '1h', label: '過去1時間' },
  { value: '6h', label: '過去6時間' },
  { value: '24h', label: '過去24時間' },
  { value: '7d', label: '過去7日間' },
  { value: 'custom', label: 'カスタム' },
];

const EVENT_TYPE_COLORS: Record<string, string> = {
  process_creation: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
  network_connection: 'bg-green-500/20 text-green-300 border-green-500/40',
  file_event: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
  registry_set: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
  dns: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
  image_load: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
  authentication: 'bg-pink-500/20 text-pink-300 border-pink-500/40',
};

const HUNT_TEMPLATES = [
  {
    id: 'powershell',
    label: '不審なPowerShell実行',
    description: 'エンコードされたコマンドやダウンロードクレードルを持つPowerShell',
    icon: <Zap className="w-4 h-4 text-yellow-400" />,
    params: { query: 'powershell', eventType: 'process_creation', processName: 'powershell.exe' },
  },
  {
    id: 'lateral',
    label: '横移動の検出',
    description: 'PsExec / WMI / SMB管理共有を利用した横移動',
    icon: <Globe className="w-4 h-4 text-blue-400" />,
    params: { query: 'psexec OR wmi OR admin$', eventType: 'network_connection' },
  },
  {
    id: 'privesc',
    label: '権限昇格の検出',
    description: 'UACバイパスやsudoの異常使用',
    icon: <Shield className="w-4 h-4 text-green-400" />,
    params: { query: 'fodhelper OR bypassuac OR sudo', eventType: 'process_creation' },
  },
  {
    id: 'c2',
    label: 'C2通信の検出',
    description: '不審なポートへの外部接続やビーコニングパターン',
    icon: <AlertTriangle className="w-4 h-4 text-orange-400" />,
    params: { query: 'beacon OR c2 OR implant', eventType: 'network_connection' },
  },
  {
    id: 'ransomware',
    label: 'ランサムウェアの挙動',
    description: 'シャドウコピー削除・大量ファイル暗号化',
    icon: <Database className="w-4 h-4 text-red-400" />,
    params: { query: 'vssadmin OR shadowcopy OR .locked OR .encrypted', eventType: 'file_event' },
  },
];

// ─── Column definitions per event type ────────────────────────────────────────

interface ColDef {
  key: string;
  label: string;
  render?: (val: unknown, row: EventRecord) => React.ReactNode;
}

const COMMON_COLS: ColDef[] = [
  {
    key: 'timestamp',
    label: '時刻',
    render: (v) => (
      <span className="font-mono text-xs whitespace-nowrap">
        {new Date(v as string).toLocaleString('ja-JP')}
      </span>
    ),
  },
  {
    key: 'event_type',
    label: 'タイプ',
    render: (v) => (
      <span
        className={`text-xs px-1.5 py-0.5 rounded-sm border whitespace-nowrap ${
          EVENT_TYPE_COLORS[v as string] ?? 'bg-[#161f33] text-[#7d92b0] border-[#1e2d42]'
        }`}
      >
        {v as string}
      </span>
    ),
  },
  { key: 'hostname', label: 'ホスト' },
];

const COLS_BY_TYPE: Record<string, ColDef[]> = {
  process_creation: [
    ...COMMON_COLS,
    { key: 'process_name', label: 'プロセス' },
    { key: 'username', label: 'ユーザー' },
    {
      key: 'severity',
      label: '重大度',
      render: (v) => {
        const n = v as number | undefined;
        if (n == null) return <span className="text-[#4a5568]">-</span>;
        const col = n >= 75 ? 'text-red-400' : n >= 50 ? 'text-orange-400' : n >= 25 ? 'text-yellow-400' : 'text-green-400';
        return <span className={`font-mono font-bold ${col}`}>{n}</span>;
      },
    },
  ],
  network_connection: [
    ...COMMON_COLS,
    { key: 'username', label: 'ユーザー' },
    {
      key: 'details',
      label: '接続先',
      render: (v) => {
        const d = v as Record<string, unknown> | undefined;
        if (!d) return <span className="text-[#4a5568]">-</span>;
        const dst = (d.dst_ip ?? d.destination_ip ?? d.remote_ip) as string | undefined;
        const port = (d.dst_port ?? d.destination_port ?? d.remote_port) as string | number | undefined;
        if (!dst) return <span className="font-mono text-xs text-[#7d92b0]">{JSON.stringify(d).slice(0, 60)}</span>;
        return (
          <span className="font-mono text-xs text-green-300">
            {dst}{port ? `:${port}` : ''}
          </span>
        );
      },
    },
  ],
  file_event: [
    ...COMMON_COLS,
    { key: 'process_name', label: 'プロセス' },
    {
      key: 'details',
      label: 'ファイルパス',
      render: (v) => {
        const d = v as Record<string, unknown> | undefined;
        const path = d && ((d.file_path ?? d.path ?? d.target_filename) as string | undefined);
        return path
          ? <span className="font-mono text-xs text-yellow-300 truncate max-w-[240px] block">{path}</span>
          : <span className="text-[#4a5568]">-</span>;
      },
    },
  ],
  authentication: [
    ...COMMON_COLS,
    { key: 'username', label: 'ユーザー' },
    {
      key: 'details',
      label: '認証情報',
      render: (v) => {
        const d = v as Record<string, unknown> | undefined;
        if (!d) return <span className="text-[#4a5568]">-</span>;
        const result = (d.result ?? d.status ?? d.auth_result) as string | undefined;
        const method = (d.method ?? d.logon_type) as string | undefined;
        return (
          <span className={`text-xs ${result?.toLowerCase().includes('fail') ? 'text-red-400' : 'text-green-400'}`}>
            {[result, method].filter(Boolean).join(' / ') || JSON.stringify(d).slice(0, 50)}
          </span>
        );
      },
    },
  ],
  dns: [
    ...COMMON_COLS,
    {
      key: 'details',
      label: 'クエリ名',
      render: (v) => {
        const d = v as Record<string, unknown> | undefined;
        const name = d && ((d.query_name ?? d.dns_query ?? d.domain) as string | undefined);
        return name
          ? <span className="font-mono text-xs text-cyan-300">{name}</span>
          : <span className="text-[#4a5568]">-</span>;
      },
    },
  ],
};

function getColumnsForResults(results: EventRecord[]): ColDef[] {
  if (results.length === 0) return COMMON_COLS;
  const firstType = results[0].event_type;
  const allSameType = results.every((r) => r.event_type === firstType);
  if (allSameType && COLS_BY_TYPE[firstType]) return COLS_BY_TYPE[firstType];

  // Mixed types — gather all top-level keys dynamically
  const keySet = new Set<string>();
  for (const r of results.slice(0, 20)) {
    for (const k of Object.keys(r)) {
      if (k !== 'id' && k !== 'details') keySet.add(k);
    }
  }
  const dynamicCols: ColDef[] = [...keySet].map((k) => ({
    key: k,
    label: k,
    render:
      k === 'event_type'
        ? (v) => (
            <span
              className={`text-xs px-1.5 py-0.5 rounded-sm border ${
                EVENT_TYPE_COLORS[v as string] ?? 'bg-[#161f33] text-[#7d92b0] border-[#1e2d42]'
              }`}
            >
              {v as string}
            </span>
          )
        : k === 'timestamp'
        ? (v) => (
            <span className="font-mono text-xs whitespace-nowrap">
              {new Date(v as string).toLocaleString('ja-JP')}
            </span>
          )
        : undefined,
  }));
  return dynamicCols;
}

// ─── Timeline helpers ──────────────────────────────────────────────────────────

interface TimelineBucket {
  time: string;
  count: number;
}

function buildTimeline(results: EventRecord[]): TimelineBucket[] {
  if (results.length === 0) return [];
  const timestamps = results.map((r) => new Date(r.timestamp).getTime()).filter((t) => !isNaN(t));
  if (timestamps.length === 0) return [];
  const min = Math.min(...timestamps);
  const max = Math.max(...timestamps);
  const range = max - min;
  const BUCKETS = 20;
  const bucketSize = range / BUCKETS || 60_000;
  const buckets: Record<number, number> = {};
  for (const t of timestamps) {
    const idx = Math.floor((t - min) / bucketSize);
    buckets[idx] = (buckets[idx] ?? 0) + 1;
  }
  return Array.from({ length: BUCKETS }, (_, i) => ({
    time: new Date(min + i * bucketSize).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }),
    count: buckets[i] ?? 0,
  }));
}

// ─── API helpers ──────────────────────────────────────────────────────────────

function timeRangeToISO(range: string): { start: string; end: string } | null {
  if (!range || range === 'custom') return null;
  const now = Date.now();
  const ms: Record<string, number> = { '1h': 36e5, '6h': 216e5, '24h': 864e5, '7d': 6048e5 };
  const delta = ms[range];
  if (!delta) return null;
  return {
    start: new Date(now - delta).toISOString(),
    end: new Date(now).toISOString(),
  };
}

async function fetchSavedHunts(): Promise<SavedHunt[]> {
  try {
    const json = await apiFetch<{ data: SavedHunt[] }>('/api/v1/threat-hunting/saved');
    return json.data ?? [];
  } catch {
    return [];
  }
}

async function createSavedHunt(payload: { name: string; description: string; params: HuntParams }): Promise<SavedHunt> {
  return apiFetch<SavedHunt>('/api/v1/threat-hunting/saved', { method: 'POST', body: JSON.stringify(payload) });
}

async function deleteSavedHunt(id: string): Promise<void> {
  await apiFetch<{ message: string }>(`/api/v1/threat-hunting/saved/${id}`, { method: 'DELETE' });
}

async function recordHuntRun(id: string): Promise<void> {
  await apiFetch<{ message: string }>(`/api/v1/threat-hunting/saved/${id}/run`, { method: 'POST' });
}

async function runHunt(params: HuntParams): Promise<HuntResult> {
  const qs = new URLSearchParams();
  if (params.query) qs.set('q', params.query);
  if (params.eventType) qs.set('event_type', params.eventType);
  if (params.hostname) qs.set('hostname', params.hostname);
  if (params.processName) qs.set('process_name', params.processName);
  if (params.username) qs.set('username', params.username);

  const rangeISO = params.timeRange ? timeRangeToISO(params.timeRange) : null;
  const startTime = rangeISO ? rangeISO.start : params.startTime;
  const endTime = rangeISO ? rangeISO.end : params.endTime;
  if (startTime) qs.set('start', startTime);
  if (endTime) qs.set('end', endTime);

  return apiFetch<HuntResult>(`/api/v1/threat-hunting/search?${qs.toString()}`);
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatBar({ label, count, max, colorClass }: { label: string; count: number; max: number; colorClass: string }) {
  const pct = max > 0 ? Math.round((count / max) * 100) : 0;
  return (
    <div className="mb-2">
      <div className="flex justify-between text-xs mb-1">
        <span className="text-[#7d92b0] truncate max-w-[140px]">{label}</span>
        <span className="text-[#e2e8f4] font-mono ml-2">{count}</span>
      </div>
      <div className="h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-500 ${colorClass}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ThreatHuntingPage() {
  const queryClient = useQueryClient();
  const canWrite = useCanWrite();

  // Query builder state
  const [queryText, setQueryText] = useState('');
  const [queryType, setQueryType] = useState('');
  const [timeRange, setTimeRange] = useState('24h');
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [hostname, setHostname] = useState('');
  const [processName, setProcessName] = useState('');
  const [username, setUsername] = useState('');
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');

  // Results state
  const [results, setResults] = useState<EventRecord[]>([]);
  const [totalResults, setTotalResults] = useState(0);
  const [execTimeMs, setExecTimeMs] = useState<number | null>(null);
  const [hasSearched, setHasSearched] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [isSearching, setIsSearching] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>('table');

  // Saved hunts sidebar
  const [savedSidebarOpen, setSavedSidebarOpen] = useState(false);
  const [loadedHuntId, setLoadedHuntId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [copiedHuntId, setCopiedHuntId] = useState<string | null>(null);

  // Save dialog
  const [saveDialogOpen, setSaveDialogOpen] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [saveDesc, setSaveDesc] = useState('');

  // Templates panel
  const [templatesOpen, setTemplatesOpen] = useState(false);

  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const { data: savedHunts = [], isLoading: savedLoading } = useQuery({
    queryKey: ['saved-hunts'],
    queryFn: fetchSavedHunts,
  });

  const createMutation = useMutation({
    mutationFn: createSavedHunt,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saved-hunts'] });
      setSaveDialogOpen(false);
      setSaveName('');
      setSaveDesc('');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteSavedHunt,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['saved-hunts'] });
      setConfirmDeleteId(null);
    },
  });

  const columns = useMemo(() => getColumnsForResults(results), [results]);
  const timelineData = useMemo(() => buildTimeline(results), [results]);

  const eventTypePills = useMemo(() => {
    const m: Record<string, number> = {};
    for (const e of results) { m[e.event_type] = (m[e.event_type] ?? 0) + 1; }
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [results]);

  const hostCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const e of results) { m[e.hostname] = (m[e.hostname] ?? 0) + 1; }
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [results]);

  const maxHost = hostCounts[0]?.[1] ?? 1;

  function exportCSV() {
    if (results.length === 0) return;
    const headers = ['timestamp', 'event_type', 'hostname', 'process_name', 'username', 'severity', 'details'];
    const rows = results.map((e) => [
      e.timestamp,
      e.event_type,
      e.hostname ?? '',
      e.process_name ?? '',
      e.username ?? '',
      e.severity ?? '',
      JSON.stringify(e.details ?? {}),
    ]);
    const csv = [headers, ...rows].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hunt-results-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function buildParams(): HuntParams {
    return { query: queryText, eventType: queryType, hostname, processName, username, startTime, endTime, timeRange };
  }

  async function handleSearch(e?: React.FormEvent) {
    if (e) e.preventDefault();
    setIsSearching(true);
    setSearchError(null);
    const t0 = performance.now();
    try {
      const params = buildParams();
      const res = await runHunt(params);
      setResults(res.data ?? []);
      setTotalResults(res.total ?? res.data?.length ?? 0);
      setExecTimeMs(Math.round(performance.now() - t0));
      setHasSearched(true);
      if (loadedHuntId) {
        recordHuntRun(loadedHuntId).then(() => queryClient.invalidateQueries({ queryKey: ['saved-hunts'] })).catch(() => {});
      }
    } catch (err) {
      setSearchError(err instanceof Error ? err.message : '検索エラー');
    } finally {
      setIsSearching(false);
    }
  }

  function handleSave() {
    if (!saveName.trim()) return;
    createMutation.mutate({ name: saveName.trim(), description: saveDesc.trim(), params: buildParams() });
  }

  function shareHunt(hunt: SavedHunt) {
    // Encode params as base64 search string, copy to clipboard
    const encoded = btoa(JSON.stringify(hunt.params))
    const shareText = `[Kizashi Hunt] ${hunt.name}\n${hunt.description ?? ''}\nParams: ${encoded}`
    navigator.clipboard.writeText(shareText).then(() => {
      setCopiedHuntId(hunt.id)
      setTimeout(() => setCopiedHuntId(null), 2000)
    })
  }

  const loadSavedHunt = useCallback((hunt: SavedHunt) => {
    setQueryText(hunt.params.query ?? '');
    setQueryType(hunt.params.eventType ?? '');
    setTimeRange(hunt.params.timeRange ?? '24h');
    setHostname(hunt.params.hostname ?? '');
    setProcessName(hunt.params.processName ?? '');
    setUsername(hunt.params.username ?? '');
    setStartTime(hunt.params.startTime ?? '');
    setEndTime(hunt.params.endTime ?? '');
    setLoadedHuntId(hunt.id);
    setSavedSidebarOpen(false);
  }, []);

  const applyTemplate = useCallback((params: HuntParams) => {
    setQueryText(params.query ?? '');
    setQueryType(params.eventType ?? '');
    setHostname(params.hostname ?? '');
    setProcessName(params.processName ?? '');
    setUsername(params.username ?? '');
    setLoadedHuntId(null);
    setTemplatesOpen(false);
  }, []);

  // Keyboard shortcut: Ctrl+Enter / Cmd+Enter to run
  function handleTextareaKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      handleSearch();
    }
  }

  return (
    <div className="min-h-screen bg-[#080c14] text-[#e2e8f4] flex flex-col">
      <PageDataUnavailable />
      <PageSaveFailed className="mb-4" />
      {/* ── Header ── */}
      <div className="border-b border-[#1e2d42] px-6 py-4 shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Terminal className="w-5 h-5 text-blue-400" />
            <div>
              <h1 className="text-xl font-semibold text-[#e2e8f4]">脅威ハンティング</h1>
              <p className="text-xs text-[#7d92b0] mt-0.5">
                イベントログを横断的に検索し、脅威を能動的に発見します
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setTemplatesOpen((v) => !v)}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                templatesOpen ? 'bg-[#1e2d42] text-[#e2e8f4]' : 'bg-[#111827] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#161f33]'
              }`}
            >
              <BookOpen className="w-4 h-4" />
              テンプレート
            </button>
            <button
              onClick={() => setSavedSidebarOpen((v) => !v)}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                savedSidebarOpen ? 'bg-blue-600 text-white' : 'bg-[#111827] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#161f33]'
              }`}
            >
              <Save className="w-4 h-4" />
              保存済み
              {savedHunts.length > 0 && (
                <span className="bg-[#1e2d42] text-[#7d92b0] text-xs px-1.5 py-0.5 rounded-full">
                  {savedHunts.length}
                </span>
              )}
            </button>
            {canWrite && hasSearched && results.length > 0 && (
              <button
                onClick={() => setSaveDialogOpen(true)}
                className="flex items-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm font-medium transition-colors"
              >
                <Save className="w-4 h-4" />
                このハントを保存
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── Templates Dropdown Panel ── */}
      {templatesOpen && (
        <div className="border-b border-[#1e2d42] bg-[#0d1524] px-6 py-4 shrink-0">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-medium text-[#7d92b0]">ハンティングテンプレート</h2>
            <button onClick={() => setTemplatesOpen(false)} className="text-[#7d92b0] hover:text-[#e2e8f4]">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
            {HUNT_TEMPLATES.map((tmpl) => (
              <button
                key={tmpl.id}
                onClick={() => applyTemplate(tmpl.params)}
                className="text-left bg-[#111827] border border-[#1e2d42] hover:border-[#2d4a6e] rounded-lg p-3 transition-colors group"
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <div className="p-1 bg-[#161f33] rounded-sm group-hover:bg-[#1e2d42] transition-colors">{tmpl.icon}</div>
                  <span className="text-xs font-medium text-[#e2e8f4] leading-tight">{tmpl.label}</span>
                </div>
                <p className="text-xs text-[#7d92b0] line-clamp-2">{tmpl.description}</p>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── Main Split Layout ── */}
      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* ── Query Builder Panel (left) ── */}
        <div className="w-80 shrink-0 border-r border-[#1e2d42] bg-[#0d1524] flex flex-col overflow-y-auto">
          <form onSubmit={handleSearch} className="flex flex-col flex-1 p-4 gap-4">

            {/* Query type selector */}
            <div>
              <label className="block text-xs font-medium text-[#7d92b0] mb-2 uppercase tracking-wider">クエリタイプ</label>
              <div className="grid grid-cols-2 gap-1.5">
                {QUERY_TYPE_OPTIONS.filter((o) => o.value !== '').map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setQueryType((v) => (v === opt.value ? '' : opt.value))}
                    className={`flex items-center gap-1.5 px-2.5 py-2 rounded-lg text-xs font-medium transition-colors ${
                      queryType === opt.value
                        ? 'bg-blue-600 text-white'
                        : 'bg-[#111827] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#161f33]'
                    }`}
                  >
                    {opt.icon}
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Query textarea (terminal style) */}
            <div>
              <label className="block text-xs font-medium text-[#7d92b0] mb-2 uppercase tracking-wider flex items-center gap-1.5">
                <Terminal className="w-3 h-3" />
                クエリ
                <span className="text-[#4a5568] font-normal normal-case tracking-normal ml-auto">Ctrl+Enter で実行</span>
              </label>
              <textarea
                ref={textareaRef}
                value={queryText}
                onChange={(e) => setQueryText(e.target.value)}
                onKeyDown={handleTextareaKeyDown}
                placeholder={'powershell AND encoded\nOR mimikatz\nOR lsass'}
                rows={6}
                className="w-full px-3 py-2.5 font-mono text-sm bg-gray-950 border border-[#1e2d42] rounded-lg text-green-300 placeholder-[#2a3a52] focus:outline-hidden focus:border-blue-500 resize-none leading-relaxed"
              />
            </div>

            {/* Time range */}
            <div>
              <label className="block text-xs font-medium text-[#7d92b0] mb-2 uppercase tracking-wider">時間範囲</label>
              <div className="grid grid-cols-2 gap-1.5">
                {TIME_RANGE_OPTIONS.filter((o) => o.value !== 'custom').map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setTimeRange(opt.value)}
                    className={`px-2.5 py-2 rounded-lg text-xs font-medium transition-colors ${
                      timeRange === opt.value
                        ? 'bg-blue-600 text-white'
                        : 'bg-[#111827] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#161f33]'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Advanced filters toggle */}
            <div>
              <button
                type="button"
                onClick={() => setAdvancedOpen((v) => !v)}
                className="flex items-center gap-1.5 text-xs text-[#7d92b0] hover:text-[#e2e8f4] transition-colors w-full"
              >
                <SlidersHorizontal className="w-3 h-3" />
                詳細フィルター
                {advancedOpen ? <ChevronUp className="w-3 h-3 ml-auto" /> : <ChevronDown className="w-3 h-3 ml-auto" />}
              </button>

              {advancedOpen && (
                <div className="mt-3 space-y-3">
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1">ホスト名</label>
                    <input
                      type="text"
                      placeholder="hostname"
                      value={hostname}
                      onChange={(e) => setHostname(e.target.value)}
                      className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-xs text-[#e2e8f4] placeholder-[#4a5568] focus:outline-hidden focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1">プロセス名</label>
                    <input
                      type="text"
                      placeholder="process_name"
                      value={processName}
                      onChange={(e) => setProcessName(e.target.value)}
                      className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-xs text-[#e2e8f4] placeholder-[#4a5568] focus:outline-hidden focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[#7d92b0] mb-1">ユーザー名</label>
                    <input
                      type="text"
                      placeholder="username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-xs text-[#e2e8f4] placeholder-[#4a5568] focus:outline-hidden focus:border-blue-500"
                    />
                  </div>
                  {timeRange === 'custom' && (
                    <>
                      <div>
                        <label className="block text-xs text-[#7d92b0] mb-1">開始時刻</label>
                        <input type="datetime-local" value={startTime} onChange={(e) => setStartTime(e.target.value)}
                          className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-xs text-[#e2e8f4] focus:outline-hidden focus:border-blue-500" />
                      </div>
                      <div>
                        <label className="block text-xs text-[#7d92b0] mb-1">終了時刻</label>
                        <input type="datetime-local" value={endTime} onChange={(e) => setEndTime(e.target.value)}
                          className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-xs text-[#e2e8f4] focus:outline-hidden focus:border-blue-500" />
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>

            {/* Action buttons */}
            <div className="flex gap-2 mt-auto pt-2">
              <button
                type="submit"
                disabled={isSearching}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-60 rounded-lg text-sm font-medium transition-colors"
              >
                {isSearching ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                {isSearching ? '実行中...' : '実行'}
              </button>
              {canWrite && (
                <button
                  type="button"
                  disabled={!queryText.trim() || isSearching}
                  onClick={() => setSaveDialogOpen(true)}
                  title="このクエリを保存"
                  className="flex items-center gap-1.5 px-3 py-2.5 bg-[#111827] border border-[#1e2d42] hover:bg-[#1e2d42] disabled:opacity-40 rounded-lg text-sm text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                >
                  <Save className="w-4 h-4" />
                  保存
                </button>
              )}
            </div>

            {/* Stats mini-sidebar */}
            {hasSearched && results.length > 0 && (
              <div className="border-t border-[#1e2d42] pt-4 space-y-4">
                <div>
                  <div className="flex items-center gap-1.5 mb-2 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">
                    <BarChart2 className="w-3 h-3" /> 上位ホスト
                  </div>
                  {hostCounts.map(([host, count]) => (
                    <StatBar key={host} label={host} count={count} max={maxHost} colorClass="bg-green-500" />
                  ))}
                </div>

                {eventTypePills.length > 0 && (
                  <div>
                    <div className="flex items-center gap-1.5 mb-2 text-xs font-medium text-[#7d92b0] uppercase tracking-wider">
                      <BarChart2 className="w-3 h-3" /> タイプ分布
                    </div>
                    {eventTypePills.map(([type, count]) => (
                      <StatBar
                        key={type}
                        label={type}
                        count={count}
                        max={eventTypePills[0]?.[1] ?? 1}
                        colorClass="bg-blue-500"
                      />
                    ))}
                  </div>
                )}
              </div>
            )}
          </form>
        </div>

        {/* ── Results Panel (right) ── */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

          {/* Results toolbar */}
          {hasSearched && (
            <div className="border-b border-[#1e2d42] bg-[#0d1524] px-4 py-2.5 flex items-center gap-3 shrink-0 flex-wrap">
              <div className="flex items-center gap-2 text-sm">
                {isSearching ? (
                  <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                ) : (
                  <span className="text-[#e2e8f4] font-medium">{totalResults.toLocaleString()}</span>
                )}
                <span className="text-[#7d92b0]">件</span>
                {execTimeMs !== null && !isSearching && (
                  <span className="text-[#4a5568] text-xs">({execTimeMs}ms)</span>
                )}
              </div>

              <div className="flex items-center gap-1 flex-wrap">
                {eventTypePills.map(([type, count]) => (
                  <span
                    key={type}
                    className={`text-xs px-2 py-0.5 rounded-full border font-mono ${
                      EVENT_TYPE_COLORS[type] ?? 'bg-[#161f33] text-[#7d92b0] border-[#1e2d42]'
                    }`}
                  >
                    {type}: {count}
                  </span>
                ))}
              </div>

              <div className="ml-auto flex items-center gap-2">
                {/* View toggle */}
                <div className="flex items-center gap-0.5 bg-[#111827] border border-[#1e2d42] rounded-lg p-0.5">
                  <button
                    onClick={() => setViewMode('table')}
                    className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm text-xs font-medium transition-colors ${
                      viewMode === 'table' ? 'bg-blue-600 text-white' : 'text-[#7d92b0] hover:text-[#e2e8f4]'
                    }`}
                  >
                    <Table2 className="w-3.5 h-3.5" />
                    テーブル
                  </button>
                  <button
                    onClick={() => setViewMode('timeline')}
                    className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-sm text-xs font-medium transition-colors ${
                      viewMode === 'timeline' ? 'bg-blue-600 text-white' : 'text-[#7d92b0] hover:text-[#e2e8f4]'
                    }`}
                  >
                    <TrendingUp className="w-3.5 h-3.5" />
                    タイムライン
                  </button>
                </div>

                <button
                  onClick={exportCSV}
                  disabled={results.length === 0}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 bg-[#111827] border border-[#1e2d42] hover:bg-[#1e2d42] disabled:opacity-40 rounded-lg text-xs text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  CSV
                </button>

                <button
                  onClick={() => handleSearch()}
                  disabled={isSearching}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 bg-[#111827] border border-[#1e2d42] hover:bg-[#1e2d42] disabled:opacity-40 rounded-lg text-xs text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isSearching ? 'animate-spin' : ''}`} />
                  再実行
                </button>
              </div>
            </div>
          )}

          {/* Results area */}
          <div className="flex-1 overflow-auto p-4">
            {/* Error */}
            {searchError && (
              <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                {searchError}
              </div>
            )}

            {/* Loading overlay */}
            {isSearching && (
              <div className="flex flex-col items-center justify-center py-20 gap-3">
                <Loader2 className="w-10 h-10 animate-spin text-blue-400" />
                <p className="text-sm text-[#7d92b0]">クエリを実行中...</p>
              </div>
            )}

            {/* Initial empty state */}
            {!hasSearched && !isSearching && (
              <div className="flex flex-col items-center justify-center py-24 gap-4">
                <div className="w-16 h-16 rounded-full bg-[#111827] border border-[#1e2d42] flex items-center justify-center">
                  <Search className="w-8 h-8 text-[#1e2d42]" />
                </div>
                <div className="text-center">
                  <p className="text-[#7d92b0] font-medium mb-1">クエリを入力して実行</p>
                  <p className="text-xs text-[#4a5568]">
                    左パネルでクエリを入力し「実行」ボタンを押すか Ctrl+Enter で検索を開始します
                  </p>
                </div>
                <div className="flex gap-2 mt-2">
                  <button
                    onClick={() => setTemplatesOpen(true)}
                    className="flex items-center gap-1.5 px-3 py-2 bg-[#111827] border border-[#1e2d42] hover:bg-[#161f33] rounded-lg text-xs text-[#7d92b0] hover:text-[#e2e8f4] transition-colors"
                  >
                    <BookOpen className="w-3.5 h-3.5" />
                    テンプレートを見る
                  </button>
                </div>
              </div>
            )}

            {/* No results */}
            {hasSearched && !isSearching && results.length === 0 && (
              <div className="flex flex-col items-center justify-center py-24 gap-4">
                <div className="w-16 h-16 rounded-full bg-[#111827] border border-[#1e2d42] flex items-center justify-center">
                  <Search className="w-8 h-8 text-[#2a3a52]" />
                </div>
                <div className="text-center">
                  <p className="text-[#7d92b0] font-medium mb-1">結果なし</p>
                  <p className="text-xs text-[#4a5568]">
                    指定した条件に一致するイベントは見つかりませんでした
                  </p>
                </div>
              </div>
            )}

            {/* Timeline view */}
            {hasSearched && !isSearching && results.length > 0 && viewMode === 'timeline' && (
              <div className="space-y-4">
                <div className="bg-[#111827] border border-[#1e2d42] rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-4">
                    <TrendingUp className="w-4 h-4 text-blue-400" />
                    <h3 className="text-sm font-medium text-[#e2e8f4]">イベント頻度タイムライン</h3>
                  </div>
                  <ResponsiveContainer width="100%" height={220}>
                    <AreaChart data={timelineData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                      <defs>
                        <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e2d42" />
                      <XAxis dataKey="time" tick={{ fill: '#7d92b0', fontSize: 10 }} tickLine={false} />
                      <YAxis tick={{ fill: '#7d92b0', fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
                      <RechartsTooltip
                        contentStyle={{ background: '#111827', border: '1px solid #1e2d42', borderRadius: 8, fontSize: 12 }}
                        labelStyle={{ color: '#e2e8f4' }}
                        itemStyle={{ color: '#3b82f6' }}
                        formatter={(v: number) => [`${v} 件`, 'イベント数']}
                      />
                      <Area type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} fill="url(#areaGrad)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>

                {/* Event type breakdown cards */}
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                  {eventTypePills.map(([type, count]) => (
                    <div key={type} className="bg-[#111827] border border-[#1e2d42] rounded-lg p-3">
                      <div className={`text-xs px-2 py-0.5 rounded-sm border inline-block mb-2 ${EVENT_TYPE_COLORS[type] ?? 'bg-[#161f33] text-[#7d92b0] border-[#1e2d42]'}`}>
                        {type}
                      </div>
                      <p className="text-xl font-bold text-[#e2e8f4] font-mono">{count}</p>
                      <p className="text-xs text-[#7d92b0]">{Math.round((count / results.length) * 100)}%</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Table view */}
            {hasSearched && !isSearching && results.length > 0 && viewMode === 'table' && (
              <div className="bg-[#111827] border border-[#1e2d42] rounded-lg overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-[#1e2d42] bg-[#0d1524]">
                        {columns.map((col) => (
                          <th
                            key={col.key}
                            className="px-3 py-2.5 text-left text-[#7d92b0] font-medium uppercase tracking-wider whitespace-nowrap"
                          >
                            {col.label}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2d42]">
                      {results.map((row, idx) => (
                        <tr
                          key={row.id ?? idx}
                          className="hover:bg-[#161f33] transition-colors group"
                        >
                          {columns.map((col) => {
                            const val = row[col.key];
                            return (
                              <td key={col.key} className="px-3 py-2 text-[#e2e8f4] max-w-[280px]">
                                {col.render
                                  ? col.render(val, row)
                                  : val == null
                                  ? <span className="text-[#4a5568]">-</span>
                                  : typeof val === 'object'
                                  ? <span className="font-mono text-[#7d92b0] truncate block">{JSON.stringify(val).slice(0, 80)}</span>
                                  : <span className="truncate block">{String(val)}</span>}
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {totalResults > results.length && (
                  <div className="px-4 py-2.5 border-t border-[#1e2d42] text-xs text-[#7d92b0] text-center bg-[#0d1524]">
                    {(results.length ?? 0).toLocaleString()} / {totalResults.toLocaleString()} 件を表示
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ── Saved Hunts Sidebar (right) ── */}
        {savedSidebarOpen && (
          <div className="w-72 shrink-0 border-l border-[#1e2d42] bg-[#0d1524] flex flex-col overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42] shrink-0">
              <h2 className="text-sm font-medium text-[#e2e8f4] flex items-center gap-2">
                <Save className="w-4 h-4 text-blue-400" />
                保存済みハント
                {savedHunts.length > 0 && (
                  <span className="text-[10px] bg-[#1e2d42] text-[#7d92b0] px-1.5 py-0.5 rounded-full">
                    {savedHunts.length}
                  </span>
                )}
              </h2>
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-[#3d5068]">
                  合計 {savedHunts.reduce((s, h) => s + h.run_count, 0)}回実行
                </span>
                <button onClick={() => setSavedSidebarOpen(false)} className="text-[#7d92b0] hover:text-[#e2e8f4]">
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-2">
              {savedLoading ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="h-16 bg-[#111827] border border-[#1e2d42] rounded-lg animate-pulse" />
                ))
              ) : savedHunts.length === 0 ? (
                <div className="text-center py-10">
                  <Save className="w-8 h-8 text-[#1e2d42] mx-auto mb-2" />
                  <p className="text-xs text-[#7d92b0]">保存済みハントはありません</p>
                </div>
              ) : (
                savedHunts.map((hunt) => (
                  <div
                    key={hunt.id}
                    className={`bg-[#111827] border rounded-lg p-3 transition-colors ${
                      loadedHuntId === hunt.id ? 'border-blue-500/60' : 'border-[#1e2d42] hover:border-[#2d4a6e]'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <h3 className="text-xs font-semibold text-[#e2e8f4] leading-tight">{hunt.name}</h3>
                      <div className="flex items-center gap-1 shrink-0">
                        <button
                          onClick={() => loadSavedHunt(hunt)}
                          title="クエリをロード"
                          className="p-1 text-blue-400 hover:text-blue-300 transition-colors"
                        >
                          <Play className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => shareHunt(hunt)}
                          title="クエリをコピーして共有"
                          className="p-1 text-[#4a5568] hover:text-green-400 transition-colors"
                        >
                          {copiedHuntId === hunt.id
                            ? <Check className="w-3.5 h-3.5 text-green-400" />
                            : <Share2 className="w-3.5 h-3.5" />
                          }
                        </button>
                        {canWrite && (confirmDeleteId === hunt.id ? (
                          <div className="flex gap-0.5">
                            <button
                              onClick={() => deleteMutation.mutate(hunt.id)}
                              disabled={deleteMutation.isPending}
                              className="px-1.5 py-0.5 bg-red-600 hover:bg-red-700 rounded-sm text-xs"
                            >
                              削除
                            </button>
                            <button
                              onClick={() => setConfirmDeleteId(null)}
                              className="px-1.5 py-0.5 bg-[#1e2d42] hover:bg-[#2a3a52] rounded-sm text-xs text-[#7d92b0]"
                            >
                              取消
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setConfirmDeleteId(hunt.id)}
                            className="p-1 text-[#4a5568] hover:text-red-400 transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        ))}
                      </div>
                    </div>
                    {hunt.description && (
                      <p className="text-xs text-[#7d92b0] mb-1.5 line-clamp-2">{hunt.description}</p>
                    )}
                    {hunt.params.query && (
                      <div className="font-mono text-xs text-[#4a5568] bg-[#080c14] rounded-sm px-2 py-1 truncate mb-1.5">
                        {hunt.params.query}
                      </div>
                    )}
                    <div className="flex items-center gap-2 text-xs text-[#4a5568]">
                      {hunt.last_run && (
                        <span className="flex items-center gap-0.5">
                          <Clock className="w-3 h-3" />
                          {new Date(hunt.last_run).toLocaleDateString('ja-JP')}
                        </span>
                      )}
                      {hunt.run_count > 0 && <span>{hunt.run_count}回実行</span>}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Save Dialog ── */}
      {saveDialogOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-[#111827] border border-[#1e2d42] rounded-xl w-full max-w-md p-6">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-base font-semibold text-[#e2e8f4]">ハントを保存</h2>
              <button onClick={() => setSaveDialogOpen(false)} className="text-[#7d92b0] hover:text-[#e2e8f4] transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1.5">
                  ハント名 <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={saveName}
                  onChange={(e) => setSaveName(e.target.value)}
                  placeholder="例: 不審なPowerShell実行の調査"
                  className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-hidden focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1.5">説明（任意）</label>
                <textarea
                  value={saveDesc}
                  onChange={(e) => setSaveDesc(e.target.value)}
                  placeholder="このハントの目的や検出対象を記述"
                  rows={3}
                  className="w-full px-3 py-2 bg-[#080c14] border border-[#1e2d42] rounded-lg text-sm text-[#e2e8f4] placeholder-[#7d92b0] focus:outline-hidden focus:border-blue-500 resize-none"
                />
              </div>
              <div className="text-xs text-[#7d92b0] bg-[#080c14] rounded-sm p-2 font-mono">
                <span className="text-[#4a5568]">クエリ: </span>{queryText || '(なし)'}
                {queryType && <><span className="text-[#4a5568]"> | タイプ: </span>{queryType}</>}
                <span className="text-[#4a5568]"> | 期間: </span>{timeRange}
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => setSaveDialogOpen(false)}
                className="flex-1 px-4 py-2.5 bg-[#161f33] hover:bg-[#1e2d42] rounded-lg text-sm font-medium transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleSave}
                disabled={!saveName.trim() || createMutation.isPending}
                className="flex-1 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 rounded-lg text-sm font-medium transition-colors"
              >
                {createMutation.isPending ? '保存中...' : '保存する'}
              </button>
            </div>
            {createMutation.isError && (
              <p className="text-red-400 text-xs mt-2 text-center">
                {(createMutation.error as Error).message}
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
