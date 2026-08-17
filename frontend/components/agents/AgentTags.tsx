'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import { Plus, X, Loader2, Tag } from 'lucide-react'
import { apiFetch } from '@/lib/api'

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_TAGS = 10

const TAG_SUGGESTIONS = [
  'production',
  'critical',
  'windows',
  'linux',
  'macos',
  'server',
  'workstation',
  'dmz',
  'isolated',
  'test',
]

// ── Tag color generator ────────────────────────────────────────────────────────

function tagColorClass(tag: string): string {
  let hash = 0
  for (let i = 0; i < tag.length; i++) {
    hash = tag.charCodeAt(i) + ((hash << 5) - hash)
  }
  const palette = [
    'bg-blue-900/50 text-blue-300 border-blue-700/50',
    'bg-purple-900/50 text-purple-300 border-purple-700/50',
    'bg-green-900/50 text-green-300 border-green-700/50',
    'bg-yellow-900/50 text-yellow-300 border-yellow-700/50',
    'bg-pink-900/50 text-pink-300 border-pink-700/50',
    'bg-cyan-900/50 text-cyan-300 border-cyan-700/50',
    'bg-orange-900/50 text-orange-300 border-orange-700/50',
    'bg-teal-900/50 text-teal-300 border-teal-700/50',
    'bg-indigo-900/50 text-indigo-300 border-indigo-700/50',
    'bg-rose-900/50 text-rose-300 border-rose-700/50',
  ]
  return palette[Math.abs(hash) % palette.length]
}

// ── TagChip ───────────────────────────────────────────────────────────────────

export interface TagChipProps {
  tag: string
  onRemove?: () => void
  removable?: boolean
}

export function TagChip({ tag, onRemove, removable = true }: TagChipProps) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium border transition-colors ${tagColorClass(tag)}`}
    >
      {tag}
      {removable && onRemove && (
        <button
          onClick={onRemove}
          aria-label={`タグ「${tag}」を削除`}
          className="ml-0.5 opacity-60 hover:opacity-100 transition-opacity shrink-0"
        >
          <X className="w-3 h-3" />
        </button>
      )}
    </span>
  )
}

// ── Props ─────────────────────────────────────────────────────────────────────

export interface AgentTagsProps {
  agentId: string
  initialTags?: string[]
  onTagsChange?: (tags: string[]) => void
}

// ── AgentTags ─────────────────────────────────────────────────────────────────

export default function AgentTags({ agentId, initialTags, onTagsChange }: AgentTagsProps) {
  const [tags, setTags] = useState<string[]>(initialTags ?? [])
  const [adding, setAdding] = useState(false)
  const [inputValue, setInputValue] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loadedFromApi, setLoadedFromApi] = useState(initialTags !== undefined)
  const [showDropdown, setShowDropdown] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  // Load tags from API on mount if not provided
  useEffect(() => {
    if (initialTags !== undefined) return
    apiFetch<{ tags?: string[] }>(`/api/v1/agents/${agentId}`)
      .then((agent) => {
        const fetched = agent.tags ?? []
        setTags(fetched)
        setLoadedFromApi(true)
      })
      .catch(() => {
        setTags([])
        setLoadedFromApi(true)
      })
  }, [agentId, initialTags])

  // Focus input when the add field appears
  useEffect(() => {
    if (adding) {
      inputRef.current?.focus()
    }
  }, [adding])

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setShowDropdown(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  const saveTags = useCallback(
    async (next: string[]) => {
      setSaving(true)
      setError(null)
      try {
        await apiFetch(`/api/v1/agents/${agentId}`, {
          method: 'PATCH',
          body: JSON.stringify({ tags: next }),
        })
        setTags(next)
        onTagsChange?.(next)
      } catch (err) {
        setError((err as Error).message ?? 'タグの保存に失敗しました')
      } finally {
        setSaving(false)
      }
    },
    [agentId, onTagsChange],
  )

  const commitInput = useCallback(async () => {
    const value = inputValue.trim().toLowerCase().replace(/\s+/g, '-')
    setAdding(false)
    setInputValue('')
    setShowDropdown(false)

    if (!value) return
    if (tags.includes(value)) return
    if (tags.length >= MAX_TAGS) {
      setError(`タグは最大${MAX_TAGS}個まで設定できます`)
      return
    }
    await saveTags([...tags, value])
  }, [inputValue, tags, saveTags])

  const handleKeyDown = async (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      if (e.nativeEvent.isComposing) return
      e.preventDefault()
      await commitInput()
    } else if (e.key === 'Escape') {
      setAdding(false)
      setInputValue('')
      setShowDropdown(false)
    }
  }

  const handleBlur = async () => {
    // slight delay so suggestion click registers before blur fires
    await new Promise((r) => setTimeout(r, 150))
    await commitInput()
  }

  const removeTag = async (tag: string) => {
    await saveTags(tags.filter((t) => t !== tag))
  }

  const addSuggestion = async (suggestion: string) => {
    setInputValue('')
    setAdding(false)
    setShowDropdown(false)
    if (tags.includes(suggestion)) return
    if (tags.length >= MAX_TAGS) {
      setError(`タグは最大${MAX_TAGS}個まで設定できます`)
      return
    }
    await saveTags([...tags, suggestion])
  }

  const filteredSuggestions = TAG_SUGGESTIONS.filter(
    (s) =>
      !tags.includes(s) &&
      (inputValue === '' || s.toLowerCase().includes(inputValue.toLowerCase())),
  )

  if (!loadedFromApi) {
    return (
      <div className="flex items-center gap-2 text-[#5a6a7a] text-sm">
        <Loader2 className="w-3.5 h-3.5 animate-spin" />
        タグを読み込み中...
      </div>
    )
  }

  return (
    <div className="bg-gray-800 rounded-xl p-4" ref={containerRef}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2 text-sm text-[#8899aa]">
          <Tag className="w-4 h-4" />
          <span>カスタムタグ</span>
          <span className="text-[#5a6a7a] text-xs">({tags.length}/{MAX_TAGS})</span>
        </div>
        {saving && <Loader2 className="w-3.5 h-3.5 animate-spin text-[#8899aa]" />}
      </div>

      {/* Tag chips */}
      <div className="flex flex-wrap gap-2 min-h-[28px]">
        {tags.length === 0 && !adding && (
          <span className="text-[#5a6a7a] text-xs italic">タグなし</span>
        )}

        {tags.map((tag) => (
          <TagChip
            key={tag}
            tag={tag}
            onRemove={() => removeTag(tag)}
            removable={!saving}
          />
        ))}

        {/* Inline input */}
        {adding && (
          <div className="relative">
            <input
              ref={inputRef}
              type="text"
              value={inputValue}
              onChange={(e) => {
                setInputValue(e.target.value)
                setShowDropdown(true)
              }}
              onFocus={() => setShowDropdown(true)}
              onKeyDown={handleKeyDown}
              onBlur={handleBlur}
              placeholder="タグ名..."
              maxLength={32}
              className="bg-falcon-card text-white text-xs px-2.5 py-1 rounded-full border border-falcon-blue/60
                         focus:outline-hidden focus:border-falcon-blue w-28 placeholder-[#5a6a7a]"
            />

            {/* Suggestion dropdown */}
            {showDropdown && filteredSuggestions.length > 0 && (
              <div
                className="absolute top-full mt-1 left-0 z-50 min-w-[160px] bg-[#1a2540]
                           border border-[#2a3a5c] rounded-lg shadow-xl overflow-hidden"
              >
                {filteredSuggestions.map((s) => (
                  <button
                    key={s}
                    onMouseDown={(e) => {
                      e.preventDefault()
                      addSuggestion(s)
                    }}
                    className="w-full text-left px-3 py-1.5 text-xs text-falcon-text
                               hover:bg-[#253050] transition-colors"
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Add button */}
        {!adding && tags.length < MAX_TAGS && (
          <button
            onClick={() => {
              setAdding(true)
              setError(null)
            }}
            disabled={saving}
            aria-label="タグを追加"
            className="inline-flex items-center justify-center w-7 h-7 rounded-full
                       border border-dashed border-falcon-subtle text-[#5a6a7a]
                       hover:border-falcon-blue hover:text-falcon-blue transition-colors
                       disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Plus className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Error */}
      {error && (
        <p className="mt-2 text-red-400 text-xs flex items-center gap-1">
          <X className="w-3 h-3 shrink-0" />
          {error}
        </p>
      )}
    </div>
  )
}
