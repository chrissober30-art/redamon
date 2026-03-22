'use client'

import { useEffect, useRef, useState, useCallback, memo } from 'react'
import { Terminal as TerminalIcon, Wifi, WifiOff, RefreshCw, Maximize2, Minimize2 } from 'lucide-react'
import styles from './KaliTerminal.module.css'

type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error'

function getWsUrl(): string {
  if (typeof window !== 'undefined') {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.hostname
    return `${protocol}//${host}:8090/ws/kali-terminal`
  }
  return 'ws://localhost:8090/ws/kali-terminal'
}

export const KaliTerminal = memo(function KaliTerminal() {
  const termRef = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const terminalRef = useRef<any>(null)
  const fitAddonRef = useRef<any>(null)
  const [status, setStatus] = useState<ConnectionStatus>('disconnected')
  const [isFullscreen, setIsFullscreen] = useState(false)
  const reconnectTimerRef = useRef<NodeJS.Timeout | null>(null)
  const inputDisposablesRef = useRef<Array<{ dispose: () => void }>>([])
  const mountedRef = useRef(true)
  const initializedRef = useRef(false)

  const connect = useCallback(async () => {
    if (!termRef.current || !mountedRef.current) return
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return

    setStatus('connecting')

    // Dynamically import xterm to avoid SSR issues
    const [{ Terminal }, { FitAddon }, { WebLinksAddon }] = await Promise.all([
      import('@xterm/xterm'),
      import('@xterm/addon-fit'),
      import('@xterm/addon-web-links'),
    ])

    if (!mountedRef.current) return

    // Only create terminal once
    if (!terminalRef.current) {
      const fitAddon = new FitAddon()
      fitAddonRef.current = fitAddon

      const terminal = new Terminal({
        cursorBlink: true,
        cursorStyle: 'block',
        fontSize: 13,
        fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Menlo', monospace",
        lineHeight: 1.3,
        letterSpacing: 0.5,
        theme: {
          background: '#0a0e14',
          foreground: '#e6e1cf',
          cursor: '#ff3333',
          cursorAccent: '#0a0e14',
          selectionBackground: '#33415580',
          selectionForeground: '#e6e1cf',
          black: '#1a1e29',
          red: '#ff3333',
          green: '#bae67e',
          yellow: '#ffd580',
          blue: '#73d0ff',
          magenta: '#d4bfff',
          cyan: '#95e6cb',
          white: '#e6e1cf',
          brightBlack: '#4d556a',
          brightRed: '#ff6666',
          brightGreen: '#91d076',
          brightYellow: '#ffe6b3',
          brightBlue: '#5ccfe6',
          brightMagenta: '#c3a6ff',
          brightCyan: '#a6f0db',
          brightWhite: '#fafafa',
        },
        scrollback: 10000,
        allowProposedApi: true,
      })

      terminal.loadAddon(fitAddon)
      terminal.loadAddon(new WebLinksAddon())

      if (termRef.current) {
        terminal.open(termRef.current)
        fitAddon.fit()
      }

      terminalRef.current = terminal
    } else {
      terminalRef.current.clear()
    }

    const terminal = terminalRef.current
    const fitAddon = fitAddonRef.current

    terminal.writeln('')
    terminal.writeln('\x1b[1;31m  ____           _    _                        \x1b[0m')
    terminal.writeln('\x1b[1;31m |  _ \\ ___  __| |  / \\   _ __ ___   ___  _ __\x1b[0m')
    terminal.writeln('\x1b[1;31m | |_) / _ \\/ _` | / _ \\ | \'_ ` _ \\ / _ \\| \'_ \\\x1b[0m')
    terminal.writeln('\x1b[1;31m |  _ <  __/ (_| |/ ___ \\| | | | | | (_) | | | |\x1b[0m')
    terminal.writeln('\x1b[1;31m |_| \\_\\___|\\__,_/_/   \\_\\_| |_| |_|\\___/|_| |_|\x1b[0m')
    terminal.writeln('')
    terminal.writeln('\x1b[1;36m  ┌──────────────────────────────────────────────┐\x1b[0m')
    terminal.writeln('\x1b[1;36m  │\x1b[0m  \x1b[1;33m⚡ Kali Sandbox Terminal\x1b[0m                      \x1b[1;36m│\x1b[0m')
    terminal.writeln('\x1b[1;36m  │\x1b[0m  \x1b[2;37mFull access to Kali Linux pentesting tools\x1b[0m   \x1b[1;36m│\x1b[0m')
    terminal.writeln('\x1b[1;36m  │\x1b[0m  \x1b[2;37mmetasploit • nmap • nuclei • hydra • sqlmap\x1b[0m  \x1b[1;36m│\x1b[0m')
    terminal.writeln('\x1b[1;36m  └──────────────────────────────────────────────┘\x1b[0m')
    terminal.writeln('')
    terminal.writeln('\x1b[2;37m  Connecting to kali-sandbox...\x1b[0m')

    const url = getWsUrl()
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.binaryType = 'arraybuffer'

    ws.onopen = () => {
      if (!mountedRef.current) {
        ws.close()
        return
      }
      setStatus('connected')
      terminal.writeln('\x1b[1;32m✓ Connected\x1b[0m\n')

      // Send terminal size
      if (fitAddon) {
        const dims = fitAddon.proposeDimensions()
        if (dims) {
          ws.send(JSON.stringify({ type: 'resize', rows: dims.rows, cols: dims.cols }))
        }
      }

      // Dispose previous input handlers before registering new ones
      inputDisposablesRef.current.forEach(d => d.dispose())
      inputDisposablesRef.current = []

      inputDisposablesRef.current.push(
        terminal.onData((data: string) => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(data)
          }
        })
      )

      inputDisposablesRef.current.push(
        terminal.onBinary((data: string) => {
          if (ws.readyState === WebSocket.OPEN) {
            const bytes = new Uint8Array(data.length)
            for (let i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i)
            ws.send(bytes.buffer)
          }
        })
      )
    }

    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        terminal.write(new Uint8Array(event.data))
      } else {
        terminal.write(event.data)
      }
    }

    ws.onerror = () => {
      if (!mountedRef.current) return
      setStatus('error')
    }

    ws.onclose = () => {
      if (!mountedRef.current) return
      setStatus('disconnected')
      terminal.writeln('\n\x1b[1;31m✗ Disconnected from kali-sandbox\x1b[0m')
      terminal.writeln('\x1b[2;37mClick "Reconnect" to establish a new session\x1b[0m')
    }
  }, [])

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    setStatus('disconnected')
  }, [])

  const reconnect = useCallback(() => {
    disconnect()
    setTimeout(() => connect(), 200)
  }, [disconnect, connect])

  const toggleFullscreen = useCallback(() => {
    setIsFullscreen(prev => !prev)
  }, [])

  // Auto-connect on mount
  useEffect(() => {
    mountedRef.current = true
    if (!initializedRef.current) {
      initializedRef.current = true
      connect()
    }
    return () => {
      mountedRef.current = false
    }
  }, [connect])

  // Handle resize
  useEffect(() => {
    const handleResize = () => {
      if (fitAddonRef.current && terminalRef.current) {
        try {
          fitAddonRef.current.fit()
          const dims = fitAddonRef.current.proposeDimensions()
          if (dims && wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify({
              type: 'resize',
              rows: dims.rows,
              cols: dims.cols,
            }))
          }
        } catch {
          // Ignore fit errors during transitions
        }
      }
    }

    const resizeObserver = new ResizeObserver(handleResize)
    if (termRef.current) {
      resizeObserver.observe(termRef.current)
    }
    window.addEventListener('resize', handleResize)

    return () => {
      resizeObserver.disconnect()
      window.removeEventListener('resize', handleResize)
    }
  }, [])

  // Refit when fullscreen toggles
  useEffect(() => {
    const timer = setTimeout(() => {
      if (fitAddonRef.current) {
        try {
          fitAddonRef.current.fit()
          const dims = fitAddonRef.current.proposeDimensions()
          if (dims && wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify({
              type: 'resize',
              rows: dims.rows,
              cols: dims.cols,
            }))
          }
        } catch {
          // Ignore
        }
      }
    }, 100)
    return () => clearTimeout(timer)
  }, [isFullscreen])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      mountedRef.current = false
      inputDisposablesRef.current.forEach(d => d.dispose())
      inputDisposablesRef.current = []
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
      if (terminalRef.current) {
        terminalRef.current.dispose()
        terminalRef.current = null
      }
    }
  }, [])

  return (
    <div className={`${styles.container} ${isFullscreen ? styles.fullscreen : ''}`}>
      <div className={styles.toolbar}>
        <div className={styles.toolbarLeft}>
          <TerminalIcon size={14} className={styles.terminalIcon} />
          <span className={styles.title}>RedAmon Terminal</span>
          <span className={styles.subtitle}>kali-sandbox</span>
        </div>
        <div className={styles.toolbarRight}>
          <span className={`${styles.statusBadge} ${styles[status]}`}>
            {status === 'connected' ? (
              <Wifi size={10} />
            ) : (
              <WifiOff size={10} />
            )}
            <span>{status}</span>
          </span>
          <button
            className={styles.toolbarBtn}
            onClick={reconnect}
            title="Reconnect"
          >
            <RefreshCw size={12} />
          </button>
          <button
            className={styles.toolbarBtn}
            onClick={toggleFullscreen}
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
          >
            {isFullscreen ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
          </button>
        </div>
      </div>
      <div ref={termRef} className={styles.terminal} />
    </div>
  )
})
