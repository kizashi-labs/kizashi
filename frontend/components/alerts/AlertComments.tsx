'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { MessageSquare, Send, Trash2, User, AlertCircle } from 'lucide-react'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

interface AlertComment {
  id: string
  content: string
  author_id: string
  author_name: string
  created_at: string
}

interface CommentsResponse {
  comments: AlertComment[]
}

interface CurrentUser {
  id: string
  username?: string
  full_name?: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function timeAgo(dateStr: string): string {
  const now = Date.now()
  const then = new Date(dateStr).getTime()
  const diff = Math.floor((now - then) / 1000)

  if (diff < 60)   return `${diff}秒前`
  if (diff < 3600) return `${Math.floor(diff / 60)}分前`
  if (diff < 86400) return `${Math.floor(diff / 3600)}時間前`
  return `${Math.floor(diff / 86400)}日前`
}

function getCurrentUser(): CurrentUser | null {
  if (typeof window === 'undefined') return null
  try {
    const raw = localStorage.getItem('user')
    if (!raw) return null
    return JSON.parse(raw) as CurrentUser
  } catch {
    return null
  }
}

// ─── Comment bubble ───────────────────────────────────────────────────────────

function CommentBubble({
  comment,
  isOwn,
  onDelete,
  isDeleting,
}: {
  comment: AlertComment
  isOwn: boolean
  onDelete: () => void
  isDeleting: boolean
}) {
  return (
    <div className="flex items-start gap-3 group">
      {/* Avatar */}
      <div className="w-8 h-8 rounded-full bg-gray-700 border border-gray-600 flex items-center justify-center shrink-0 mt-0.5">
        <User className="w-4 h-4 text-gray-400" />
      </div>

      {/* Bubble */}
      <div className="flex-1 min-w-0">
        <div className="bg-gray-700 rounded-xl rounded-tl-sm px-4 py-3 border border-gray-600">
          <div className="flex items-center justify-between gap-2 mb-1.5">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-white">
                {comment.author_name}
              </span>
              {isOwn && (
                <span className="text-xs text-blue-400 bg-blue-900/30 border border-blue-700/40 px-1.5 py-0.5 rounded-full">
                  自分
                </span>
              )}
            </div>
            <span className="text-xs text-gray-500 whitespace-nowrap shrink-0">
              {timeAgo(comment.created_at)}
            </span>
          </div>
          <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap break-words">
            {comment.content}
          </p>
        </div>

        {/* Delete button (own comments only) */}
        {isOwn && (
          <div className="flex justify-end mt-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <button
              onClick={onDelete}
              disabled={isDeleting}
              className="flex items-center gap-1 px-2 py-1 text-xs text-gray-500 hover:text-red-400 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              title="削除"
            >
              <Trash2 className="w-3 h-3" />
              削除
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function AlertComments({ alertId }: { alertId: string }) {
  const qc = useQueryClient()
  const [content, setContent] = useState('')
  const currentUser = getCurrentUser()

  // Fetch comments — handle 404 gracefully
  const {
    data,
    isLoading,
    isError,
    error,
  } = useQuery<CommentsResponse>({
    queryKey: ['alert-comments', alertId],
    queryFn: () => apiFetch<CommentsResponse>(`/api/v1/alerts/${alertId}/comments`),
    retry: (failureCount, err) => {
      // Do not retry on 404
      if ((err as Error).message.includes('404') || (err as Error).message.includes('HTTP 404')) {
        return false
      }
      return failureCount < 2
    },
  })

  // Post comment
  const postMutation = useMutation({
    mutationFn: (body: { content: string }) =>
      apiFetch(`/api/v1/alerts/${alertId}/comments`, {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert-comments', alertId] })
      setContent('')
    },
  })

  // Delete comment
  const deleteMutation = useMutation({
    mutationFn: (commentId: string) =>
      apiFetch(`/api/v1/alerts/${alertId}/comments/${commentId}`, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert-comments', alertId] })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = content.trim()
    if (!trimmed || postMutation.isPending) return
    postMutation.mutate({ content: trimmed })
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      const trimmed = content.trim()
      if (trimmed && !postMutation.isPending) {
        postMutation.mutate({ content: trimmed })
      }
    }
  }

  // ─── 404 / feature-not-ready state ──────────────────────────────────────────

  const is404 =
    isError &&
    ((error as Error).message.includes('404') ||
      (error as Error).message.includes('HTTP 404'))

  if (is404) {
    return (
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
        <div className="flex items-center gap-2 mb-4">
          <MessageSquare className="w-5 h-5 text-gray-400" />
          <h2 className="text-base font-semibold text-white">コメント</h2>
        </div>
        <div className="flex flex-col items-center justify-center py-8 gap-3">
          <div className="w-12 h-12 rounded-full bg-gray-700 flex items-center justify-center">
            <AlertCircle className="w-6 h-6 text-gray-500" />
          </div>
          <p className="text-gray-400 text-sm text-center">コメント機能は準備中です</p>
        </div>
      </div>
    )
  }

  // ─── Generic error state ─────────────────────────────────────────────────────

  if (isError) {
    return (
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
        <div className="flex items-center gap-2 mb-4">
          <MessageSquare className="w-5 h-5 text-gray-400" />
          <h2 className="text-base font-semibold text-white">コメント</h2>
        </div>
        <div className="bg-red-900/20 border border-red-700/30 rounded-lg p-4">
          <p className="text-red-400 text-sm">
            コメントの読み込みに失敗しました: {(error as Error).message}
          </p>
        </div>
      </div>
    )
  }

  const comments = data?.comments ?? []

  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 space-y-5">
      <PageSaveFailed className="mb-4" />
      {/* Header */}
      <div className="flex items-center gap-2">
        <MessageSquare className="w-5 h-5 text-gray-400" />
        <h2 className="text-base font-semibold text-white">コメント</h2>
        {!isLoading && (
          <span className="text-xs text-gray-500 bg-gray-700 px-2 py-0.5 rounded-full">
            {comments.length}
          </span>
        )}
      </div>

      {/* Comment list */}
      {isLoading ? (
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="flex items-start gap-3 animate-pulse">
              <div className="w-8 h-8 rounded-full bg-gray-700 shrink-0" />
              <div className="flex-1 space-y-2">
                <div className="h-3 bg-gray-700 rounded-sm w-24" />
                <div className="h-14 bg-gray-700 rounded-xl" />
              </div>
            </div>
          ))}
        </div>
      ) : comments.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 gap-2">
          <MessageSquare className="w-8 h-8 text-gray-600" />
          <p className="text-gray-500 text-sm">まだコメントはありません</p>
        </div>
      ) : (
        <div className="space-y-4">
          {comments.map(comment => (
            <CommentBubble
              key={comment.id}
              comment={comment}
              isOwn={!!currentUser && comment.author_id === currentUser.id}
              onDelete={() => deleteMutation.mutate(comment.id)}
              isDeleting={deleteMutation.isPending && deleteMutation.variables === comment.id}
            />
          ))}
        </div>
      )}

      {/* Divider */}
      <div className="border-t border-gray-700" />

      {/* Input form */}
      <form onSubmit={handleSubmit} className="space-y-3">
        <textarea
          value={content}
          onChange={e => setContent(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="コメントを入力... (Ctrl+Enter で送信)"
          rows={3}
          className="w-full bg-gray-900 border border-gray-600 rounded-xl px-4 py-3 text-sm text-gray-200 placeholder-gray-500 resize-none focus:outline-hidden focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors"
        />

        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-gray-600">
            {content.length > 0 ? `${content.length} 文字` : ''}
          </p>
          <div className="flex items-center gap-2">
            {postMutation.isError && (
              <p className="text-xs text-red-400">
                {(postMutation.error as Error).message}
              </p>
            )}
            <button
              type="submit"
              disabled={!content.trim() || postMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {postMutation.isPending ? (
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              送信
            </button>
          </div>
        </div>
      </form>
    </div>
  )
}
