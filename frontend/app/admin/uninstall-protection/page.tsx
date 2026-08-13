'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { ShieldOff, ShieldCheck, KeyRound, AlertTriangle, RefreshCw } from 'lucide-react'
import { ViewerGuard } from '@/components/ViewerGuard'
import { useCanWrite } from '@/lib/auth'

interface ProtectionStatus {
  configured: boolean
  updated_at?: string
  updated_by?: string
  algorithm?: string
  iterations?: number
}

interface UninstallAttempt {
  id: number
  agent_id?: string
  hostname?: string
  authorised: boolean
  occurred_at: string
}

interface AttemptsResponse {
  data: UninstallAttempt[]
  total: number
}

// The password is never returned by the API — the server keeps only a PBKDF2
// digest — so this page can show whether one is set and when it was rotated,
// but it can never show the value. Reflected in the UI so an operator does not
// go looking for a "reveal" button that cannot exist.
const MIN_PASSWORD_LENGTH = 12

export default function UninstallProtectionPage() {
  const queryClient = useQueryClient()
  const canWrite = useCanWrite()
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [deniedOnly, setDeniedOnly] = useState(true)
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)

  const { data: status, isLoading } = useQuery<ProtectionStatus>({
    queryKey: ['uninstall-protection'],
    queryFn: () => apiFetch('/api/v1/admin/uninstall-protection'),
  })

  const { data: attempts } = useQuery<AttemptsResponse>({
    queryKey: ['uninstall-attempts', deniedOnly],
    queryFn: () =>
      apiFetch(`/api/v1/admin/uninstall-protection/attempts?denied_only=${deniedOnly}&limit=100`),
  })

  const setMutation = useMutation({
    mutationFn: (pw: string) =>
      apiFetch<{ ok: boolean; note?: string }>('/api/v1/admin/uninstall-protection', {
        method: 'POST',
        body: JSON.stringify({ password: pw }),
      }),
    onSuccess: (res) => {
      setPassword('')
      setConfirmPassword('')
      setMessage({ kind: 'ok', text: res.note ?? 'アンインストールパスワードを設定しました。' })
      queryClient.invalidateQueries({ queryKey: ['uninstall-protection'] })
    },
    onError: (e: Error) => setMessage({ kind: 'error', text: e.message }),
  })

  const clearMutation = useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; note?: string }>('/api/v1/admin/uninstall-protection', {
        method: 'DELETE',
      }),
    onSuccess: (res) => {
      setMessage({ kind: 'ok', text: res.note ?? 'アンインストール保護を解除しました。' })
      queryClient.invalidateQueries({ queryKey: ['uninstall-protection'] })
    },
    onError: (e: Error) => setMessage({ kind: 'error', text: e.message }),
  })

  const tooShort = password.length > 0 && password.length < MIN_PASSWORD_LENGTH
  const mismatch = confirmPassword.length > 0 && password !== confirmPassword
  const canSubmit =
    canWrite && password.length >= MIN_PASSWORD_LENGTH && password === confirmPassword

  const deniedCount = (attempts?.data ?? []).filter((a) => !a.authorised).length

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <KeyRound className="w-6 h-6" />
          アンインストール保護
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          エージェントの削除にパスワードを要求します。端末のローカル管理者権限を取った攻撃者が
          最初に行うのはセンサの除去で、ここが通ると以降の可視性がまるごと失われます。
        </p>
      </div>

      {message && (
        <div
          className={`rounded-md border p-3 text-sm ${
            message.kind === 'ok'
              ? 'border-green-600/40 bg-green-600/10'
              : 'border-red-600/40 bg-red-600/10'
          }`}
        >
          {message.text}
        </div>
      )}

      {/* ─── Current state ─────────────────────────────────────── */}
      <section className="rounded-lg border p-4">
        <h2 className="font-semibold mb-3">現在の状態</h2>
        {isLoading ? (
          <p className="text-sm text-muted-foreground">読み込み中…</p>
        ) : status?.configured ? (
          <div className="space-y-1 text-sm">
            <p className="flex items-center gap-2 text-green-500 font-medium">
              <ShieldCheck className="w-4 h-4" />
              有効 — アンインストールにはパスワードが必要です
            </p>
            <p className="text-muted-foreground">
              最終更新: {new Date(status.updated_at!).toLocaleString('ja-JP')}
              {status.updated_by ? `（${status.updated_by}）` : ''}
            </p>
            <p className="text-muted-foreground">
              鍵導出: {status.algorithm} / {status.iterations?.toLocaleString('ja-JP')} 回
            </p>
          </div>
        ) : (
          <p className="flex items-center gap-2 text-sm text-amber-500 font-medium">
            <ShieldOff className="w-4 h-4" />
            未設定 — どの端末も無条件にアンインストールできます
          </p>
        )}
      </section>

      {/* ─── Set / rotate ──────────────────────────────────────── */}
      <ViewerGuard>
        <section className="rounded-lg border p-4 space-y-3">
          <h2 className="font-semibold">
            {status?.configured ? 'パスワードをローテートする' : 'パスワードを設定する'}
          </h2>

          <div className="rounded-md border border-amber-600/40 bg-amber-600/10 p-3 text-sm space-y-1">
            <p className="flex items-center gap-2 font-medium">
              <AlertTriangle className="w-4 h-4" />
              設定後にパスワードを表示することはできません
            </p>
            <p className="text-muted-foreground">
              サーバは PBKDF2 のダイジェストだけを保持し、平文はどこにも保存しません。
              紛失した場合は再設定（ローテート）してください。
            </p>
          </div>

          <div className="grid gap-3 max-w-md">
            <label className="text-sm">
              新しいパスワード
              <input
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 w-full rounded-md border bg-background px-3 py-2"
                placeholder={`${MIN_PASSWORD_LENGTH} 文字以上`}
              />
              {tooShort && (
                <span className="text-xs text-red-500">
                  {MIN_PASSWORD_LENGTH} 文字以上にしてください。ダイジェストは保護対象の各端末上に
                  置かれるため、短いパスワードはオフラインで総当たりされます。
                </span>
              )}
            </label>

            <label className="text-sm">
              確認のためもう一度
              <input
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="mt-1 w-full rounded-md border bg-background px-3 py-2"
              />
              {mismatch && <span className="text-xs text-red-500">一致しません</span>}
            </label>

            <div className="flex gap-2">
              <button
                type="button"
                disabled={!canSubmit || setMutation.isPending}
                onClick={() => setMutation.mutate(password)}
                className="rounded-md bg-primary px-4 py-2 text-sm text-primary-foreground disabled:opacity-50"
              >
                {setMutation.isPending ? '設定中…' : status?.configured ? 'ローテート' : '設定'}
              </button>

              {status?.configured && (
                <button
                  type="button"
                  disabled={!canWrite || clearMutation.isPending}
                  onClick={() => {
                    if (
                      confirm(
                        '保護を解除すると、どの端末も無条件にアンインストールできるようになります。続行しますか？'
                      )
                    ) {
                      clearMutation.mutate()
                    }
                  }}
                  className="rounded-md border border-red-600/50 px-4 py-2 text-sm text-red-500 disabled:opacity-50"
                >
                  保護を解除
                </button>
              )}
            </div>

            <p className="text-xs text-muted-foreground">
              各エンドポイントには次回ハートビート時（既定30秒間隔）に配布されます。
              配布が済むまでの端末は直前のパスワードのままです。
            </p>
          </div>
        </section>
      </ViewerGuard>

      {/* ─── Attempts ──────────────────────────────────────────── */}
      <section className="rounded-lg border p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-semibold">
            アンインストール試行
            {deniedCount > 0 && (
              <span className="ml-2 rounded-full bg-red-600/20 px-2 py-0.5 text-xs text-red-400">
                拒否 {deniedCount} 件
              </span>
            )}
          </h2>
          <div className="flex items-center gap-3">
            <label className="text-sm flex items-center gap-2">
              <input
                type="checkbox"
                checked={deniedOnly}
                onChange={(e) => setDeniedOnly(e.target.checked)}
              />
              拒否されたものだけ
            </label>
            <button
              type="button"
              onClick={() =>
                queryClient.invalidateQueries({ queryKey: ['uninstall-attempts'] })
              }
              className="rounded-md border px-2 py-1 text-sm flex items-center gap-1"
            >
              <RefreshCw className="w-3 h-3" />
              更新
            </button>
          </div>
        </div>

        {(attempts?.data ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {deniedOnly
              ? '拒否された試行はありません。'
              : 'アンインストール試行の記録はありません。'}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-muted-foreground border-b">
                  <th className="py-2 pr-4">日時</th>
                  <th className="py-2 pr-4">ホスト</th>
                  <th className="py-2 pr-4">結果</th>
                  <th className="py-2">エージェントID</th>
                </tr>
              </thead>
              <tbody>
                {(attempts?.data ?? []).map((a) => (
                  <tr key={a.id} className="border-b last:border-0">
                    <td className="py-2 pr-4 whitespace-nowrap">
                      {new Date(a.occurred_at).toLocaleString('ja-JP')}
                    </td>
                    <td className="py-2 pr-4">{a.hostname || '—'}</td>
                    <td className="py-2 pr-4">
                      {a.authorised ? (
                        <span className="text-muted-foreground">承認（正規の削除）</span>
                      ) : (
                        <span className="text-red-500 font-medium">拒否（パスワード不一致）</span>
                      )}
                    </td>
                    <td className="py-2 font-mono text-xs text-muted-foreground">
                      {a.agent_id || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <p className="text-xs text-muted-foreground mt-3">
          この通報経路は認証を要求しません。通報元は「まさに削除されようとしているエージェント」で、
          攻撃者が先に資格情報を無効化している場合が多く、認証を要求すると最も見たい通報だけが
          届かなくなるためです。代わりにこの一覧は追記専用で、エージェントの状態は変更しません。
        </p>
      </section>
    </div>
  )
}
