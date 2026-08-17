'use client'

import { useState, useEffect } from 'react'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'

interface BackupCode {
  code: string
  used: boolean
  used_at?: string
}

interface BackupCodesResponse {
  codes: BackupCode[]
  generated_at: string
  usage_history?: { code: string; used_at: string }[]
}

export default function MFABackupCodesPage() {
  const [codes, setCodes] = useState<BackupCode[]>([])
  const [generatedAt, setGeneratedAt] = useState<string>('')
  const [usageHistory, setUsageHistory] = useState<{ code: string; used_at: string }[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notConfigured, setNotConfigured] = useState(false)
  const [copySuccess, setCopySuccess] = useState(false)
  const [showConfirmModal, setShowConfirmModal] = useState(false)
  const [regenerating, setRegenerating] = useState(false)

  const fetchCodes = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiFetch<BackupCodesResponse>('/api/v1/auth/mfa/backup-codes')
      setCodes(data.codes ?? [])
      setGeneratedAt(data.generated_at ?? '')
      setUsageHistory(data.usage_history ?? [])
    } catch (err: unknown) {
      const e = err as Error
      if (e.message?.includes('404') || e.message?.includes('HTTP 404')) {
        setNotConfigured(true)
      } else {
        // Never show fabricated backup codes — they would not work at login.
        setError('バックアップコードを取得できませんでした。時間をおいて再度お試しください。')
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchCodes()
  }, [])

  const handleCopy = async () => {
    const text = codes.map(c => c.code).join('\n')
    try {
      await navigator.clipboard.writeText(text)
      setCopySuccess(true)
      setTimeout(() => setCopySuccess(false), 2000)
    } catch {
      setError('クリップボードへのコピーに失敗しました')
    }
  }

  const handlePrint = () => {
    window.print()
  }

  const handleRegenerate = async () => {
    setRegenerating(true)
    setShowConfirmModal(false)
    try {
      const data = await apiFetch<BackupCodesResponse>('/api/v1/auth/mfa/backup-codes/regenerate', {
        method: 'POST',
      })
      setCodes(data.codes ?? [])
      setGeneratedAt(data.generated_at ?? new Date().toISOString())
      setUsageHistory(data.usage_history ?? [])
      setError(null)
    } catch (err: unknown) {
      const e = err as Error
      setError('コードの再生成に失敗しました: ' + e.message)
    } finally {
      setRegenerating(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <p className="text-gray-400 text-sm">読み込み中...</p>
      </div>
    )
  }

  if (notConfigured) {
    return (
      <div className="min-h-screen bg-gray-900 p-6">
        <div className="max-w-2xl mx-auto">
          <div className="flex items-center gap-3 mb-6">
            <Link
              href="/settings"
              className="text-gray-400 hover:text-white text-sm transition-colors"
            >
              &larr; 設定に戻る
            </Link>
          </div>
          <div className="bg-gray-800 rounded-lg p-6 text-center">
            <div className="text-yellow-400 text-4xl mb-4">&#9888;</div>
            <p className="text-gray-300">
              MFAバックアップコードは設定されていません。まずMFAを有効化してください。
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-900 p-6">
      <div className="max-w-2xl mx-auto space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link
              href="/settings"
              className="text-gray-400 hover:text-white text-sm transition-colors"
            >
              &larr; 設定に戻る
            </Link>
          </div>
          <h1 className="text-xl font-semibold text-white">MFAバックアップコード</h1>
          <div className="w-24" />
        </div>

        {/* Error banner */}
        {error && (
          <div className="bg-red-900/40 border border-red-700 rounded-lg p-3">
            <p className="text-red-300 text-sm">{error}</p>
          </div>
        )}

        {/* Info card */}
        <div className="bg-gray-800 rounded-lg p-5 border border-gray-700">
          <h2 className="text-white font-medium mb-2">バックアップコードとは</h2>
          <p className="text-gray-400 text-sm leading-relaxed">
            バックアップコードは、認証アプリにアクセスできない場合のログインに使用できる緊急アクセスコードです。
            各コードは1回のみ使用可能です。安全な場所に保管してください。
          </p>
          {generatedAt && (
            <p className="text-gray-500 text-xs mt-3">
              生成日時: {new Date(generatedAt).toLocaleString('ja-JP')}
            </p>
          )}
        </div>

        {/* Backup codes display card */}
        <div className="bg-gray-800 rounded-lg p-5 border border-gray-700">
          <h2 className="text-white font-medium mb-4">バックアップコード一覧</h2>
          <div className="grid grid-cols-2 gap-3">
            {codes.map((item, idx) => (
              <div
                key={idx}
                className={`bg-gray-700 rounded px-4 py-2 flex items-center justify-between ${
                  item.used ? 'opacity-50' : ''
                }`}
              >
                <span
                  className={`font-mono text-sm tracking-widest ${
                    item.used ? 'line-through text-gray-500' : 'text-green-400'
                  }`}
                >
                  {item.code}
                </span>
                {item.used && (
                  <span className="text-xs text-red-400 bg-red-900/40 px-2 py-0.5 rounded-sm ml-2 whitespace-nowrap">
                    使用済み
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="flex flex-wrap gap-3">
          <button
            onClick={handleCopy}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            {copySuccess ? 'コピーしました!' : 'コードをコピー'}
          </button>
          <button
            onClick={handlePrint}
            className="flex items-center gap-2 bg-gray-600 hover:bg-gray-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            PDFとして保存
          </button>
          <button
            onClick={() => setShowConfirmModal(true)}
            disabled={regenerating}
            className="flex items-center gap-2 bg-red-700 hover:bg-red-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
          >
            {regenerating ? '生成中...' : '新しいコードを生成'}
          </button>
        </div>

        {/* Warning card */}
        <div className="bg-yellow-900/30 border border-yellow-700 rounded-lg p-4">
          <p className="text-yellow-300 text-sm font-medium">
            注意: 新しいコードを生成すると、現在のコードは無効になります
          </p>
        </div>

        {/* Usage history */}
        {usageHistory.length > 0 && (
          <div className="bg-gray-800 rounded-lg p-5 border border-gray-700">
            <h2 className="text-white font-medium mb-4">使用履歴</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-400 border-b border-gray-700">
                    <th className="text-left pb-2 font-medium">コード</th>
                    <th className="text-left pb-2 font-medium">使用日時</th>
                  </tr>
                </thead>
                <tbody>
                  {usageHistory.map((entry, idx) => (
                    <tr key={idx} className="border-b border-gray-700/50">
                      <td className="py-2 font-mono text-gray-300">{entry.code}</td>
                      <td className="py-2 text-gray-400">
                        {new Date(entry.used_at).toLocaleString('ja-JP')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Confirm Regenerate Modal */}
      {showConfirmModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 max-w-md w-full mx-4 shadow-2xl">
            <h3 className="text-white font-semibold text-lg mb-3">コードを再生成しますか？</h3>
            <p className="text-gray-400 text-sm mb-6">
              現在のバックアップコードはすべて無効になります。この操作は元に戻せません。
            </p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setShowConfirmModal(false)}
                className="px-4 py-2 text-sm text-gray-300 hover:text-white bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
              >
                キャンセル
              </button>
              <button
                onClick={handleRegenerate}
                className="px-4 py-2 text-sm text-white bg-red-700 hover:bg-red-600 rounded-lg transition-colors"
              >
                再生成する
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
