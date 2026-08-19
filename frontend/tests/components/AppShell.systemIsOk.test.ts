import { describe, it, expect } from 'vitest'
import { systemIsOk } from '@/components/layout/AppShell'

// ヘッダーの「SYSTEM OK / DEGRADED」。
//
// 以前は `!healthData || healthData.status === 'ok'` でした。/health が
// 500 を返すと本文の JSON 解析に失敗し、healthData は undefined になります。
// 左辺が真になるので、答えられなかったヘルスチェックが SYSTEM OK として
// 表示されます。いちばん状態を知りたいときに緑になる作りでした。
describe('systemIsOk', () => {
  it.each([
    { name: 'ok が返った', health: { status: 'ok' }, want: true },
    { name: 'degraded が返った', health: { status: 'degraded' }, want: false },
    { name: '読めなかった (undefined)', health: undefined, want: false },
    { name: '読めなかった (null)', health: null, want: false },
  ])('$name', ({ health, want }) => {
    expect(systemIsOk(health)).toBe(want)
  })
})
