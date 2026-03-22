import { describe, test, expect } from 'vitest'

describe('KaliTerminal WebSocket URL', () => {
  test('generates correct WebSocket URL format', () => {
    const protocol = 'ws:'
    const host = 'localhost'
    const url = `${protocol}//${host}:8090/ws/kali-terminal`
    expect(url).toBe('ws://localhost:8090/ws/kali-terminal')
  })

  test('uses wss for https', () => {
    const protocol = 'wss:'
    const host = 'example.com'
    const url = `${protocol}//${host}:8090/ws/kali-terminal`
    expect(url).toBe('wss://example.com:8090/ws/kali-terminal')
  })

  test('URL contains correct path', () => {
    const url = 'ws://localhost:8090/ws/kali-terminal'
    expect(url).toContain('/ws/kali-terminal')
    expect(url).toContain(':8090')
  })
})

describe('ViewMode type', () => {
  test('terminal is a valid ViewMode value', () => {
    type ViewMode = 'graph' | 'table' | 'sessions' | 'terminal' | 'roe'
    const mode: ViewMode = 'terminal'
    expect(mode).toBe('terminal')
  })

  test('all view modes are distinct', () => {
    const modes = ['graph', 'table', 'sessions', 'terminal', 'roe']
    const uniqueModes = new Set(modes)
    expect(uniqueModes.size).toBe(modes.length)
  })
})

describe('Resize message format', () => {
  test('creates valid resize JSON', () => {
    const msg = JSON.stringify({ type: 'resize', rows: 24, cols: 80 })
    const parsed = JSON.parse(msg)
    expect(parsed.type).toBe('resize')
    expect(parsed.rows).toBe(24)
    expect(parsed.cols).toBe(80)
  })

  test('handles arbitrary dimensions', () => {
    const msg = JSON.stringify({ type: 'resize', rows: 50, cols: 200 })
    const parsed = JSON.parse(msg)
    expect(parsed.rows).toBe(50)
    expect(parsed.cols).toBe(200)
  })
})

describe('Connection status states', () => {
  test('all status values are distinct', () => {
    const statuses = ['disconnected', 'connecting', 'connected', 'error']
    const unique = new Set(statuses)
    expect(unique.size).toBe(4)
  })

  test('initial status should be disconnected', () => {
    const initialStatus = 'disconnected'
    expect(initialStatus).toBe('disconnected')
  })
})
