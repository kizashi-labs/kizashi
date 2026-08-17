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
  red:    { accent: '#e8002d', bg: 'bg-falcon-red/8',  text: 'text-[#ff4d6d]',  border: 'border-falcon-red/20' },
  orange: { accent: '#ff6b35', bg: 'bg-[#ff6b35]/8',  text: 'text-[#ff8c5a]',  border: 'border-[#ff6b35]/20' },
  yellow: { accent: '#ff9800', bg: 'bg-falcon-amber/8',  text: 'text-[#ffb74d]',  border: 'border-falcon-amber/20' },
  blue:   { accent: '#1a6bff', bg: 'bg-falcon-blue/8',  text: 'text-[#5a99ff]',  border: 'border-falcon-blue/20' },
  cyan:   { accent: '#00b8d4', bg: 'bg-falcon-cyan/8',  text: 'text-[#00e5ff]',  border: 'border-falcon-cyan/20' },
  green:  { accent: '#00c853', bg: 'bg-falcon-green/8',  text: 'text-[#00e676]',  border: 'border-falcon-green/20' },
  gray:   { accent: '#3d5068', bg: 'bg-falcon-subtle/15', text: 'text-falcon-muted',  border: 'border-falcon-subtle/30' },
}

const SUBTEXT_COLOR = {
  red:   'text-[#ff4d6d]',
  green: 'text-[#00e676]',
  gray:  'text-falcon-muted',
  amber: 'text-[#ffb74d]',
}

export function StatCard({
  title, value, icon, color,
  subtext, subtextColor = 'gray', trend, href,
}: StatCardProps) {
  const c = COLOR_MAP[color]
  const sc = SUBTEXT_COLOR[subtextColor]

  const inner = (
    <div className={`relative bg-falcon-card border ${c.border} rounded-md p-4 overflow-hidden
                     transition-all duration-150 hover:bg-falcon-raised
                     shadow-falcon-card group`}>
      {/* Top accent bar */}
      <div className="absolute top-0 left-0 right-0 h-[2px] rounded-t-md"
           style={{ background: `linear-gradient(90deg, ${c.accent}, transparent)` }} />

      <div className="flex items-start justify-between">
        <div className="min-w-0 flex-1">
          <p className="text-[10px] font-semibold tracking-widest uppercase text-falcon-muted mb-2">
            {title}
          </p>
          <p className="text-2xl font-bold text-falcon-text tabular-nums leading-none">
            {value}
          </p>
          {subtext && (
            <p className={`text-[11px] mt-1.5 font-medium ${sc}`}>{subtext}</p>
          )}
          {trend !== undefined && (
            <p className={`text-[10px] mt-1 font-semibold ${
              trend > 0 ? 'text-[#ff4d6d]' : trend < 0 ? 'text-[#00e676]' : 'text-falcon-muted'
            }`}>
              {trend > 0 ? '↑' : trend < 0 ? '↓' : '→'} {Math.abs(trend)}% vs 前日
            </p>
          )}
        </div>
        <div className={`w-10 h-10 rounded ${c.bg} flex items-center justify-center ${c.text}
                         transition-transform group-hover:scale-110 duration-150 shrink-0 ml-3`}>
          {icon}
        </div>
      </div>
    </div>
  )

  return href ? <a href={href}>{inner}</a> : inner
}
