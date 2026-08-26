import { describe, it, expect, beforeEach } from 'vitest'
import { getStoredVitals, clearStoredVitals, type VitalEntry } from '@/lib/vitals'

const STORAGE_KEY = 'edr_web_vitals'

function entry(name: string, value: number): VitalEntry {
  return {
    name,
    value,
    rating: 'good',
    delta: value,
    id: `${name}-1`,
    navigationType: 'navigate',
    timestamp: 1,
  }
}

describe('vitals storage', () => {
  beforeEach(() => {
    sessionStorage.clear()
  })

  it('未保存時は空配列を返す', () => {
    expect(getStoredVitals()).toEqual([])
  })

  it('保存済みエントリをパースして返す', () => {
    const data = [entry('LCP', 1200), entry('CLS', 0.05)]
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(data))
    expect(getStoredVitals()).toEqual(data)
  })

  it('壊れた JSON でも例外を投げず空配列を返す', () => {
    sessionStorage.setItem(STORAGE_KEY, '{not-valid-json')
    expect(getStoredVitals()).toEqual([])
  })

  it('clearStoredVitals は保存データを削除する', () => {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify([entry('FCP', 900)]))
    clearStoredVitals()
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull()
    expect(getStoredVitals()).toEqual([])
  })
})
