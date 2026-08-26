import React from 'react'

interface StatCardProps {
  title: string
  value: number | string
  icon: React.ReactNode
  color: 'blue' | 'green' | 'red' | 'orange' | 'yellow' | 'gray' | 'cyan'
  subtext?: string
  subtextColor?: 'red' | 'green' | 'gray' | 'amber'
  trend?: number  // % change, positive = up
  href?: string
}

const COLOR_MAP = {
  red:    { accent: '#e8002d', bg: 'bg-[#e8002d]/8',  text: 'text-[#ff4d6d]',  border: 'border-[#e8002d]/20' },
  orange: { accent: '#ff6b35', bg: 'bg-[#ff6b35]/8',  text: 'text-[#ff8c5a]',  border: 'border-[#ff6b35]/20' },
  yellow: { accent: '#ff9800', bg: 'bg-[#ff9800]/8',  text: 'text-[#ffb74d]',  border: 'border-[#ff9800]/20' },
  blue:   { accent: '#1a6bff', bg: 'bg-[#1a6bff]/8',  text: 'text-[#5a99ff]',  border: 'border-[#1a6bff]/20' },
  cyan:   { accent: '#00b8d4', bg: 'bg-[#00b8d4]/8',  text: 'text-[#00e5ff]',  border: 'border-[#00b8d4]/20' },
  green:  { accent: '#00c853', bg: 'bg-[#00c853]/8',  text: 'text-[#00e676]',  border: 'border-[#00c853]/20' },
  gray:   { accent: '#3d5068', bg: 'bg-[#3d5068]/15', text: 'text-[#7d92b0]',  border: 'border-[#3d5068]/30' },
}

const SUBTEXT_COLOR = {
  red:   'text-[#ff4d6d]',
  green: 'text-[#00e676]',
  gray:  'text-[#7d92b0]',
  amber: 'text-[#ffb74d]',
}

export function StatCard({
  title, value, icon, color,
  subtext, subtextColor = 'gray', trend, href,
}: StatCardProps) {
  const c = COLOR_MAP[color]
  const sc = SUBTEXT_COLOR[subtextColor]

  const inner = (
    <div className={`relative bg-[#111827] border ${c.border} rounded-md p-4 overflow-hidden
                     transition-all duration-150 hover:border-opacity-60 hover:bg-[#161f33]
                     shadow-falcon-card group`}>
      {/* Top accent bar */}
      <div className="absolute top-0 left-0 right-0 h-[2px] rounded-t-md"
           style={{ background: `linear-gradient(90deg, ${c.accent}, transparent)` }} />

      <div className="flex items-start justify-between">
        <div className="min-w-0 flex-1">
          <p className="text-[10px] font-semibold tracking-widest uppercase text-[#7d92b0] mb-2">
            {title}
          </p>
          <p className="text-2xl font-bold text-[#e2e8f4] tabular-nums leading-none">
            {value}
          </p>
          {subtext && (
            <p className={`text-[11px] mt-1.5 font-medium ${sc}`}>{subtext}</p>
          )}
          {trend !== undefined && (
            <p className={`text-[10px] mt-1 font-semibold ${
              trend > 0 ? 'text-[#ff4d6d]' : trend < 0 ? 'text-[#00e676]' : 'text-[#7d92b0]'
            }`}>
              {trend > 0 ? '↑' : trend < 0 ? '↓' : '→'} {Math.abs(trend)}% vs 前日
            </p>
          )}
        </div>
        <div className={`w-10 h-10 rounded-sm ${c.bg} flex items-center justify-center ${c.text}
                         transition-transform group-hover:scale-110 duration-150 shrink-0 ml-3`}>
          {icon}
        </div>
      </div>
    </div>
  )

  return href ? <a href={href}>{inner}</a> : inner
}
