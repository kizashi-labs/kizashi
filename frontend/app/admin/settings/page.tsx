'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Palette, Bell, Monitor, Shield, Save, Check,
  Sun, Moon, Laptop, Trash2, Volume2, VolumeX,
} from 'lucide-react'

// ── Types ───────────────────────────────────────────────────────────────────

type Theme = 'dark' | 'light' | 'system'
type AccentColor = 'blue' | 'red' | 'green' | 'purple' | 'orange' | 'cyan'
type FontSize = 'normal' | 'large' | 'xl'
type DateFormat = 'relative' | 'absolute'
type TimezoneDisplay = 'utc' | 'local'
type TableDensity = 'compact' | 'normal' | 'comfortable'
type ItemsPerPage = 25 | 50 | 100
type SessionTimeout = '1h' | '4h' | '8h' | 'never'
type PollingInterval = '15' | '30' | '60'

interface AppSettings {
  theme: Theme
  accentColor: AccentColor
  fontSize: FontSize
  browserNotifications: boolean
  soundAlerts: boolean
  pollingInterval: PollingInterval
  dateFormat: DateFormat
  timezone: TimezoneDisplay
  tableDensity: TableDensity
  itemsPerPage: ItemsPerPage
  sessionTimeout: SessionTimeout
}

// ── Constants ───────────────────────────────────────────────────────────────

const PREFIX = 'edr_setting_'

const ACCENT_COLORS: { id: AccentColor; class: string; label: string }[] = [
  { id: 'blue',   class: 'bg-blue-500',   label: 'ブルー'   },
  { id: 'red',    class: 'bg-red-500',    label: 'レッド'    },
  { id: 'green',  class: 'bg-green-500',  label: 'グリーン'  },
  { id: 'purple', class: 'bg-purple-500', label: 'パープル' },
  { id: 'orange', class: 'bg-orange-500', label: 'オレンジ' },
  { id: 'cyan',   class: 'bg-cyan-500',   label: 'シアン'   },
]

const ACCENT_CSS: Record<AccentColor, string> = {
  blue:   '#3b82f6',
  red:    '#ef4444',
  green:  '#22c55e',
  purple: '#a855f7',
  orange: '#f97316',
  cyan:   '#06b6d4',
}

const DEFAULT_SETTINGS: AppSettings = {
  theme:                'dark',
  accentColor:          'red',
  fontSize:             'normal',
  browserNotifications: false,
  soundAlerts:          false,
  pollingInterval:      '30',
  dateFormat:           'relative',
  timezone:             'utc',
  tableDensity:         'normal',
  itemsPerPage:         25,
  sessionTimeout:       '4h',
}

// ── Persistence helpers ─────────────────────────────────────────────────────

function loadSettings(): AppSettings {
  if (typeof window === 'undefined') return DEFAULT_SETTINGS
  const saved: Partial<AppSettings> = {}
  for (const key of Object.keys(DEFAULT_SETTINGS) as (keyof AppSettings)[]) {
    const raw = localStorage.getItem(PREFIX + key)
    if (raw !== null) {
      const defaultVal = DEFAULT_SETTINGS[key]
      if (typeof defaultVal === 'boolean') {
        (saved as Record<string, unknown>)[key] = raw === 'true'
      } else if (typeof defaultVal === 'number') {
        (saved as Record<string, unknown>)[key] = Number(raw)
      } else {
        (saved as Record<string, unknown>)[key] = raw
      }
    }
  }
  return { ...DEFAULT_SETTINGS, ...saved }
}

function saveSettings(settings: AppSettings) {
  for (const key of Object.keys(settings) as (keyof AppSettings)[]) {
    localStorage.setItem(PREFIX + key, String(settings[key]))
  }
}

function clearSettings() {
  for (const key of Object.keys(DEFAULT_SETTINGS)) {
    localStorage.removeItem(PREFIX + key)
  }
  localStorage.removeItem('edr_accent_color')
  localStorage.removeItem('edr_locale')
}

// ── Toast ───────────────────────────────────────────────────────────────────

function Toast({ message, visible }: { message: string; visible: boolean }) {
  return (
    <div className={`fixed top-6 right-6 z-50 flex items-center gap-2 px-4 py-3 rounded-lg
      bg-green-900/90 border border-green-700 text-green-300 text-sm font-medium shadow-xl
      transition-all duration-300 ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 -translate-y-2 pointer-events-none'}`}>
      <Check className="w-4 h-4" />
      {message}
    </div>
  )
}

// ── Section wrapper ─────────────────────────────────────────────────────────

function Section({ title, icon: Icon, children }: {
  title: string
  icon: React.ComponentType<{ className?: string }>
  children: React.ReactNode
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <Icon className="w-4 h-4 text-zinc-400" />
        <h2 className="text-sm font-semibold text-zinc-200 uppercase tracking-wider">{title}</h2>
      </div>
      <div className="space-y-4">{children}</div>
    </div>
  )
}

// ── Row ─────────────────────────────────────────────────────────────────────

function Row({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-2 py-2 border-b border-zinc-800 last:border-0">
      <div className="sm:w-56 flex-shrink-0">
        <div className="text-sm text-zinc-300">{label}</div>
        {desc && <div className="text-xs text-zinc-500 mt-0.5">{desc}</div>}
      </div>
      <div className="flex-1">{children}</div>
    </div>
  )
}

// ── Toggle ──────────────────────────────────────────────────────────────────

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`relative w-10 h-6 rounded-full transition-colors ${checked ? 'bg-red-600' : 'bg-zinc-700'}`}
    >
      <span className={`absolute top-1 w-4 h-4 rounded-full bg-[#e2e8f4] shadow transition-transform ${checked ? 'left-5' : 'left-1'}`} />
    </button>
  )
}

// ── Select ──────────────────────────────────────────────────────────────────

function Select<T extends string | number>({
  value, onChange, options,
}: {
  value: T
  onChange: (v: T) => void
  options: { value: T; label: string }[]
}) {
  return (
    <select
      value={String(value)}
      onChange={e => {
        const raw = e.target.value
        const match = options.find(o => String(o.value) === raw)
        if (match) onChange(match.value)
      }}
      className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-1.5 text-sm text-zinc-200 focus:outline-none focus:border-zinc-500 transition-colors"
    >
      {options.map(o => (
        <option key={String(o.value)} value={String(o.value)}>{o.label}</option>
      ))}
    </select>
  )
}

// ── Radio group ─────────────────────────────────────────────────────────────

function RadioGroup<T extends string>({
  value, onChange, options,
}: {
  value: T
  onChange: (v: T) => void
  options: { value: T; label: string; disabled?: boolean }[]
}) {
  return (
    <div className="flex flex-wrap gap-2">
      {options.map(o => (
        <button
          key={o.value}
          onClick={() => !o.disabled && onChange(o.value)}
          disabled={o.disabled}
          className={`px-3 py-1.5 rounded-lg text-sm font-medium border transition-colors
            ${value === o.value
              ? 'bg-red-600 border-red-500 text-white'
              : 'bg-zinc-800 border-zinc-700 text-zinc-300 hover:border-zinc-600 hover:text-zinc-100'
            }
            ${o.disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          {o.label}
          {o.disabled && <span className="ml-1 text-xs opacity-70">(近日公開)</span>}
        </button>
      ))}
    </div>
  )
}

// ── Main Page ───────────────────────────────────────────────────────────────

export default function AppearanceSettingsPage() {
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS)
  const [toastVisible, setToastVisible] = useState(false)
  const [notifPermission, setNotifPermission] = useState<NotificationPermission | null>(null)

  useEffect(() => {
    setSettings(loadSettings())
    if (typeof Notification !== 'undefined') {
      setNotifPermission(Notification.permission)
    }
  }, [])

  // Apply accent color CSS variable
  useEffect(() => {
    document.documentElement.style.setProperty('--edr-accent', ACCENT_CSS[settings.accentColor])
    localStorage.setItem('edr_accent_color', settings.accentColor)
  }, [settings.accentColor])

  const update = useCallback(<K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    setSettings(prev => ({ ...prev, [key]: value }))
  }, [])

  const handleSave = () => {
    saveSettings(settings)
    setToastVisible(true)
    setTimeout(() => setToastVisible(false), 3000)
  }

  const handleClearPrefs = () => {
    clearSettings()
    setSettings(DEFAULT_SETTINGS)
    setToastVisible(true)
    setTimeout(() => setToastVisible(false), 3000)
  }

  const requestNotifPermission = async () => {
    if (typeof Notification === 'undefined') return
    const result = await Notification.requestPermission()
    setNotifPermission(result)
    update('browserNotifications', result === 'granted')
  }

  return (
    <div className="min-h-screen bg-zinc-950 p-6">
      <Toast message="設定を保存しました" visible={toastVisible} />

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Palette className="w-6 h-6 text-zinc-400" />
          <div>
            <h1 className="text-xl font-bold text-zinc-100">外観と設定</h1>
            <p className="text-xs text-zinc-500 mt-0.5">プラットフォームの表示設定をカスタマイズ</p>
          </div>
        </div>
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors"
        >
          <Save className="w-4 h-4" />
          設定を保存
        </button>
      </div>

      <div className="max-w-3xl space-y-5">

        {/* Appearance */}
        <Section title="外観" icon={Sun}>
          <Row label="テーマ" desc="プラットフォームのカラースキーム">
            <RadioGroup<Theme>
              value={settings.theme}
              onChange={v => update('theme', v)}
              options={[
                { value: 'dark', label: <span className="flex items-center gap-1.5"><Moon className="w-3.5 h-3.5" />ダーク</span> as unknown as string },
                { value: 'light', label: <span className="flex items-center gap-1.5"><Sun className="w-3.5 h-3.5" />ライト</span> as unknown as string, disabled: true },
                { value: 'system', label: <span className="flex items-center gap-1.5"><Laptop className="w-3.5 h-3.5" />システム</span> as unknown as string, disabled: true },
              ]}
            />
          </Row>

          <Row label="アクセントカラー" desc="ボタンやアクティブナビゲーションの色">
            <div className="flex gap-2">
              {ACCENT_COLORS.map(c => (
                <button
                  key={c.id}
                  onClick={() => update('accentColor', c.id)}
                  title={c.label}
                  className={`w-7 h-7 rounded-full ${c.class} transition-all ${
                    settings.accentColor === c.id
                      ? 'ring-2 ring-white ring-offset-2 ring-offset-zinc-900 scale-110'
                      : 'hover:scale-110'
                  }`}
                />
              ))}
            </div>
          </Row>

          <Row label="フォントサイズ" desc="インターフェース全体のテキストサイズ">
            <RadioGroup<FontSize>
              value={settings.fontSize}
              onChange={v => update('fontSize', v)}
              options={[
                { value: 'normal', label: '標準' },
                { value: 'large',  label: '大'  },
                { value: 'xl',     label: '特大' },
              ]}
            />
          </Row>
        </Section>

        {/* Notifications */}
        <Section title="通知" icon={Bell}>
          <Row label="ブラウザ通知" desc={`権限: ${notifPermission === 'granted' ? '許可' : notifPermission === 'denied' ? '拒否' : '未設定'}`}>
            <div className="flex items-center gap-3">
              <Toggle
                checked={settings.browserNotifications && notifPermission === 'granted'}
                onChange={v => {
                  if (v && notifPermission !== 'granted') {
                    requestNotifPermission()
                  } else {
                    update('browserNotifications', v)
                  }
                }}
              />
              {notifPermission === 'denied' && (
                <span className="text-xs text-yellow-500">ブラウザでブロックされています</span>
              )}
            </div>
          </Row>
          <Row label="サウンド通知" desc="新しいクリティカルアラート時にサウンドを再生">
            <div className="flex items-center gap-2">
              <Toggle
                checked={settings.soundAlerts}
                onChange={v => update('soundAlerts', v)}
              />
              {settings.soundAlerts
                ? <Volume2 className="w-4 h-4 text-zinc-400" />
                : <VolumeX className="w-4 h-4 text-zinc-600" />
              }
            </div>
          </Row>
          <Row label="ポーリング間隔" desc="新しいアラートの確認頻度">
            <Select<PollingInterval>
              value={settings.pollingInterval}
              onChange={v => update('pollingInterval', v)}
              options={[
                { value: '15', label: '15秒ごと' },
                { value: '30', label: '30秒ごと' },
                { value: '60', label: '60秒ごと' },
              ]}
            />
          </Row>
        </Section>

        {/* Display */}
        <Section title="表示" icon={Monitor}>
          <Row label="日付形式" desc="アプリ全体での日付の表示方法">
            <RadioGroup<DateFormat>
              value={settings.dateFormat}
              onChange={v => update('dateFormat', v)}
              options={[
                { value: 'relative', label: '相対表示 (2時間前)' },
                { value: 'absolute', label: '絶対表示 (2024-03-18 14:30)' },
              ]}
            />
          </Row>
          <Row label="タイムゾーン表示" desc="タイムスタンプに使用するタイムゾーン">
            <RadioGroup<TimezoneDisplay>
              value={settings.timezone}
              onChange={v => update('timezone', v)}
              options={[
                { value: 'utc',   label: 'UTC'   },
                { value: 'local', label: 'ローカル' },
              ]}
            />
          </Row>
          <Row label="テーブル密度" desc="データテーブルの行間隔">
            <RadioGroup<TableDensity>
              value={settings.tableDensity}
              onChange={v => update('tableDensity', v)}
              options={[
                { value: 'compact',     label: 'コンパクト'     },
                { value: 'normal',      label: '標準'      },
                { value: 'comfortable', label: 'ゆったり' },
              ]}
            />
          </Row>
          <Row label="1ページあたりの件数" desc="ページネーションテーブルのデフォルト行数">
            <Select<ItemsPerPage>
              value={settings.itemsPerPage}
              onChange={v => update('itemsPerPage', v)}
              options={[
                { value: 25,  label: '25件' },
                { value: 50,  label: '50件' },
                { value: 100, label: '100件' },
              ]}
            />
          </Row>
        </Section>

        {/* Security */}
        <Section title="セキュリティ" icon={Shield}>
          <Row label="セッションタイムアウト" desc="操作なしの場合の自動ログアウト時間">
            <Select<SessionTimeout>
              value={settings.sessionTimeout}
              onChange={v => update('sessionTimeout', v)}
              options={[
                { value: '1h',   label: '1時間'   },
                { value: '4h',   label: '4時間'  },
                { value: '8h',   label: '8時間'  },
                { value: 'never', label: 'なし'   },
              ]}
            />
          </Row>
          <Row label="設定をリセット" desc="すべての設定をデフォルトに戻す">
            <button
              onClick={handleClearPrefs}
              className="flex items-center gap-2 px-3 py-1.5 bg-zinc-800 hover:bg-red-900/40 border border-zinc-700 hover:border-red-700 text-zinc-400 hover:text-red-300 text-sm rounded-lg transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              設定をリセット
            </button>
          </Row>
        </Section>

        {/* Save footer */}
        <div className="flex justify-end pt-2">
          <button
            onClick={handleSave}
            className="flex items-center gap-2 px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Save className="w-4 h-4" />
            設定を保存
          </button>
        </div>
      </div>
    </div>
  )
}
