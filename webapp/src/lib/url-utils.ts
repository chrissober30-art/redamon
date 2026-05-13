export function isHttpUrl(value: unknown): value is string {
  return typeof value === 'string' && /^https?:\/\//i.test(value)
}

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
// Hostname must end with an alphabetic TLD of at least 2 chars (avoids matching version strings like "1.0").
const HOSTNAME_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i
const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i
const CWE_RE = /^CWE-(\d+)$/i
const CAPEC_RE = /^CAPEC-(\d+)$/i
const GITHUB_SLUG_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/
const HOST_PORT_RE = /^(.+):(\d{1,5})$/

// Common file/code extensions that look like TLDs but aren't — used by resolveLinkable
// to avoid auto-linkifying things like "config.xml" or "package.json".
const NON_DOMAIN_TLDS = new Set([
  'json', 'xml', 'html', 'htm', 'css', 'js', 'ts', 'tsx', 'jsx', 'mjs', 'cjs',
  'py', 'rb', 'go', 'rs', 'php', 'java', 'kt', 'swift', 'scala', 'cs', 'fs',
  'c', 'h', 'cpp', 'hpp', 'cc', 'hh', 'sh', 'bash', 'zsh', 'fish',
  'md', 'rst', 'txt', 'log', 'csv', 'tsv',
  'yml', 'yaml', 'toml', 'ini', 'conf', 'cfg', 'env', 'lock',
  'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'bmp', 'tiff', 'pdf',
  'zip', 'tar', 'gz', 'bz2', 'xz', 'tgz', 'rar', '7z',
  'exe', 'dll', 'so', 'dylib', 'war', 'jar', 'ear', 'pyc', 'pyo', 'class',
  'key', 'pem', 'csr', 'crt', 'cer', 'pfx', 'p12',
  'map', 'min', 'bak', 'swp', 'tmp', 'orig', 'old',
  'tcp', 'udp', 'icmp',
])

export function isIpv4(value: unknown): value is string {
  return typeof value === 'string' && IPV4_RE.test(value)
}

export function isHostname(value: unknown): value is string {
  return typeof value === 'string' && HOSTNAME_RE.test(value) && !IPV4_RE.test(value)
}

export function isEmail(value: unknown): value is string {
  return typeof value === 'string' && EMAIL_RE.test(value)
}

export function isCveId(value: unknown): value is string {
  return typeof value === 'string' && CVE_RE.test(value)
}

export function isCweId(value: unknown): value is string {
  return typeof value === 'string' && CWE_RE.test(value)
}

export function isCapecId(value: unknown): value is string {
  return typeof value === 'string' && CAPEC_RE.test(value)
}

export function isGithubSlug(value: unknown): value is string {
  if (typeof value !== 'string') return false
  if (!GITHUB_SLUG_RE.test(value)) return false
  // Avoid matching version specs like "lib/1.2.3" or paths with file extensions
  if (/^\d+(\.\d+)*$/.test(value.split('/')[1] ?? '')) return false
  return true
}

export function parseHostPort(value: unknown): { host: string; port: number } | null {
  if (typeof value !== 'string') return null
  const m = value.match(HOST_PORT_RE)
  if (!m) return null
  const port = Number(m[2])
  if (!Number.isFinite(port) || port < 1 || port > 65535) return null
  const host = m[1]
  if (!isIpv4(host) && !isHostname(host)) return null
  return { host, port }
}

export function ipToUrl(ip: string, port?: number): string {
  if (port === 443) return `https://${ip}`
  if (port) return `http://${ip}:${port}`
  return `http://${ip}`
}

export function hostToUrl(host: string): string {
  return `https://${host.replace(/\.$/, '')}`
}

export function hostPortToUrl(host: string, port: number): string {
  const h = host.replace(/\.$/, '')
  if (port === 443) return `https://${h}`
  if (port === 80) return `http://${h}`
  // Default to http for non-standard ports — the more common case for recon targets
  return `http://${h}:${port}`
}

export function cveToUrl(id: string): string {
  return `https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}`
}

export function cweToUrl(id: string): string {
  const m = id.match(CWE_RE)
  const num = m ? m[1] : id.replace(/^CWE-/i, '')
  return `https://cwe.mitre.org/data/definitions/${num}.html`
}

export function capecToUrl(id: string): string {
  const m = id.match(CAPEC_RE)
  const num = m ? m[1] : id.replace(/^CAPEC-/i, '')
  return `https://capec.mitre.org/data/definitions/${num}.html`
}

export function githubSlugToUrl(slug: string): string {
  return `https://github.com/${slug}`
}

export function emailToMailto(email: string): string {
  return `mailto:${email}`
}

function tldOf(host: string): string {
  const dot = host.lastIndexOf('.')
  return dot >= 0 ? host.slice(dot + 1).toLowerCase() : ''
}

/**
 * Best-effort link resolver for arbitrary string values rendered in tables/drawers.
 * Returns a URL if the value matches a known pattern, or null otherwise.
 *
 * Rejects common file-extension TLDs (e.g. "config.xml") to avoid false positives
 * in auto-linkified contexts like ListCell and the Node Drawer.
 */
export function resolveLinkable(value: unknown): string | null {
  if (typeof value !== 'string') return null
  // Strip a single trailing dot — DNS records sometimes carry one (e.g. "example.com.").
  const v = value.trim().replace(/\.$/, '')
  if (!v) return null
  if (isHttpUrl(v)) return v
  if (isCveId(v)) return cveToUrl(v)
  if (isCweId(v)) return cweToUrl(v)
  if (isCapecId(v)) return capecToUrl(v)
  if (isEmail(v)) return emailToMailto(v)
  const hp = parseHostPort(v)
  if (hp) {
    if (isIpv4(hp.host)) return hostPortToUrl(hp.host, hp.port)
    if (!NON_DOMAIN_TLDS.has(tldOf(hp.host))) return hostPortToUrl(hp.host, hp.port)
    return null
  }
  if (isIpv4(v)) return ipToUrl(v)
  if (isHostname(v) && !NON_DOMAIN_TLDS.has(tldOf(v))) return hostToUrl(v)
  return null
}
