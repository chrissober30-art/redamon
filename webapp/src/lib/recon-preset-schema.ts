import { z } from 'zod/v4'

// ---------------------------------------------------------------------------
// Zod schema covering every recon-pipeline parameter from the Prisma Project
// model.  All fields are optional (presets are Partial<ProjectFormData>).
// Unknown keys are stripped so the LLM cannot inject garbage.
// ---------------------------------------------------------------------------

const bool = z.boolean().optional()
const int = z.coerce.number().int().optional()
const float = z.coerce.number().optional()
const str = z.string().optional()
const strArr = z.array(z.string()).optional()
const intArr = z.array(z.coerce.number().int()).optional()

export const reconPresetSchema = z.object({
  // -- Global --
  scanModules: strArr,
  stealthMode: bool,
  updateGraphDb: bool,
  useTorForRecon: bool,
  useBruteforceForSubdomains: bool,

  // -- WHOIS / DNS --
  whoisEnabled: bool,
  whoisMaxRetries: int,
  dnsEnabled: bool,
  dnsMaxRetries: int,
  dnsMaxWorkers: int,
  dnsRecordParallelism: bool,

  // -- Subdomain Discovery --
  subdomainDiscoveryEnabled: bool,
  crtshEnabled: bool,
  crtshMaxResults: int,
  hackerTargetEnabled: bool,
  hackerTargetMaxResults: int,
  knockpyReconEnabled: bool,
  knockpyReconMaxResults: int,
  subfinderEnabled: bool,
  subfinderMaxResults: int,
  amassEnabled: bool,
  amassMaxResults: int,
  amassTimeout: int,
  amassActive: bool,
  amassBrute: bool,
  purednsEnabled: bool,
  purednsThreads: int,
  purednsRateLimit: int,
  purednsWildcardBatch: int,
  purednsSkipValidation: bool,

  // -- Port Scanning: Naabu --
  naabuEnabled: bool,
  naabuTopPorts: str,
  naabuCustomPorts: str,
  naabuRateLimit: int,
  naabuThreads: int,
  naabuTimeout: int,
  naabuRetries: int,
  naabuScanType: str,
  naabuExcludeCdn: bool,
  naabuDisplayCdn: bool,
  naabuSkipHostDiscovery: bool,
  naabuVerifyPorts: bool,
  naabuPassiveMode: bool,

  // -- Port Scanning: Masscan --
  masscanEnabled: bool,
  masscanTopPorts: str,
  masscanCustomPorts: str,
  masscanRate: int,
  masscanBanners: bool,
  masscanWait: int,
  masscanRetries: int,
  masscanExcludeTargets: str,

  // -- Port Scanning: Nmap --
  nmapEnabled: bool,
  nmapVersionDetection: bool,
  nmapScriptScan: bool,
  nmapTimingTemplate: str,
  nmapTimeout: int,
  nmapHostTimeout: int,
  nmapParallelism: int,

  // -- HTTP Probing: httpx --
  httpxEnabled: bool,
  httpxThreads: int,
  httpxTimeout: int,
  httpxRetries: int,
  httpxRateLimit: int,
  httpxFollowRedirects: bool,
  httpxMaxRedirects: int,
  httpxProbeStatusCode: bool,
  httpxProbeContentLength: bool,
  httpxProbeContentType: bool,
  httpxProbeTitle: bool,
  httpxProbeServer: bool,
  httpxProbeResponseTime: bool,
  httpxProbeWordCount: bool,
  httpxProbeLineCount: bool,
  httpxProbeTechDetect: bool,
  httpxProbeIp: bool,
  httpxProbeCname: bool,
  httpxProbeTlsInfo: bool,
  httpxProbeTlsGrab: bool,
  httpxProbeFavicon: bool,
  httpxProbeJarm: bool,
  httpxProbeHash: str,
  httpxIncludeResponse: bool,
  httpxIncludeResponseHeaders: bool,
  httpxProbeAsn: bool,
  httpxProbeCdn: bool,
  httpxPaths: strArr,
  httpxCustomHeaders: strArr,
  httpxMatchCodes: strArr,
  httpxFilterCodes: strArr,

  // -- Wappalyzer --
  wappalyzerEnabled: bool,
  wappalyzerMinConfidence: int,
  wappalyzerRequireHtml: bool,
  wappalyzerAutoUpdate: bool,
  wappalyzerCacheTtlHours: int,

  // -- Banner Grabbing --
  bannerGrabEnabled: bool,
  bannerGrabTimeout: int,
  bannerGrabThreads: int,
  bannerGrabMaxLength: int,

  // -- Web Crawling: Katana --
  katanaEnabled: bool,
  katanaDepth: int,
  katanaMaxUrls: int,
  katanaRateLimit: int,
  katanaTimeout: int,
  katanaJsCrawl: bool,
  katanaParamsOnly: bool,
  katanaExcludePatterns: strArr,
  katanaScope: str,
  katanaCustomHeaders: strArr,
  katanaParallelism: int,
  katanaConcurrency: int,

  // -- Web Crawling: Hakrawler --
  hakrawlerEnabled: bool,
  hakrawlerDepth: int,
  hakrawlerThreads: int,
  hakrawlerTimeout: int,
  hakrawlerMaxUrls: int,
  hakrawlerIncludeSubs: bool,
  hakrawlerInsecure: bool,
  hakrawlerParallelism: int,

  // -- JS Analysis: jsluice --
  jsluiceEnabled: bool,
  jsluiceMaxFiles: int,
  jsluiceTimeout: int,
  jsluiceExtractUrls: bool,
  jsluiceExtractSecrets: bool,
  jsluiceConcurrency: int,
  jsluiceParallelism: int,

  // -- JS Analysis: JS Recon --
  jsReconEnabled: bool,
  jsReconMaxFiles: int,
  jsReconTimeout: int,
  jsReconConcurrency: int,
  jsReconValidateKeys: bool,
  jsReconValidationTimeout: int,
  jsReconExtractEndpoints: bool,
  jsReconRegexPatterns: bool,
  jsReconSourceMaps: bool,
  jsReconDependencyCheck: bool,
  jsReconDomSinks: bool,
  jsReconFrameworkDetect: bool,
  jsReconDevComments: bool,
  jsReconIncludeChunks: bool,
  jsReconIncludeFrameworkJs: bool,
  jsReconIncludeArchivedJs: bool,
  jsReconMinConfidence: str,
  jsReconStandaloneCrawlDepth: int,

  // -- Directory Fuzzing: ffuf --
  ffufEnabled: bool,
  ffufWordlist: str,
  ffufThreads: int,
  ffufRate: int,
  ffufTimeout: int,
  ffufMaxTime: int,
  ffufMatchCodes: intArr,
  ffufFilterCodes: intArr,
  ffufFilterSize: str,
  ffufExtensions: strArr,
  ffufRecursion: bool,
  ffufRecursionDepth: int,
  ffufAutoCalibrate: bool,
  ffufFollowRedirects: bool,
  ffufSmartFuzz: bool,
  ffufParallelism: int,

  // -- Parameter Discovery: Arjun --
  arjunEnabled: bool,
  arjunThreads: int,
  arjunTimeout: int,
  arjunScanTimeout: int,
  arjunMethods: strArr,
  arjunMaxEndpoints: int,
  arjunChunkSize: int,
  arjunRateLimit: int,
  arjunStable: bool,
  arjunPassive: bool,
  arjunDisableRedirects: bool,

  // -- Passive URL Discovery: GAU --
  gauEnabled: bool,
  gauProviders: strArr,
  gauMaxUrls: int,
  gauTimeout: int,
  gauThreads: int,
  gauBlacklistExtensions: strArr,
  gauVerbose: bool,
  gauVerifyUrls: bool,
  gauDetectMethods: bool,
  gauFilterDeadEndpoints: bool,
  gauWorkers: int,

  // -- ParamSpider --
  paramspiderEnabled: bool,
  paramspiderTimeout: int,
  paramspiderWorkers: int,

  // -- API Discovery: Kiterunner --
  kiterunnerEnabled: bool,
  kiterunnerWordlists: strArr,
  kiterunnerRateLimit: int,
  kiterunnerConnections: int,
  kiterunnerTimeout: int,
  kiterunnerScanTimeout: int,
  kiterunnerThreads: int,
  kiterunnerDetectMethods: bool,
  kiterunnerMethodDetectionMode: str,
  kiterunnerBruteforceMethods: strArr,
  kiterunnerParallelism: int,

  // -- Vulnerability Scanning: Nuclei --
  nucleiEnabled: bool,
  nucleiSeverity: strArr,
  nucleiTemplates: strArr,
  nucleiExcludeTemplates: strArr,
  nucleiCustomTemplates: strArr,
  nucleiRateLimit: int,
  nucleiBulkSize: int,
  nucleiConcurrency: int,
  nucleiTimeout: int,
  nucleiRetries: int,
  nucleiTags: strArr,
  nucleiExcludeTags: strArr,
  nucleiDastMode: bool,
  nucleiAutoUpdateTemplates: bool,
  nucleiNewTemplatesOnly: bool,
  nucleiHeadless: bool,
  nucleiSystemResolvers: bool,
  nucleiFollowRedirects: bool,
  nucleiMaxRedirects: int,
  nucleiScanAllIps: bool,
  nucleiInteractsh: bool,

  // -- CVE Lookup --
  cveLookupEnabled: bool,
  cveLookupSource: str,
  cveLookupMaxCves: int,
  cveLookupMinCvss: float,

  // -- MITRE CWE/CAPEC --
  mitreEnabled: bool,
  mitreAutoUpdateDb: bool,
  mitreIncludeCwe: bool,
  mitreIncludeCapec: bool,
  mitreEnrichRecon: bool,
  mitreEnrichGvm: bool,
  mitreCacheTtlHours: int,

  // -- Security Checks --
  securityCheckEnabled: bool,
  securityCheckDirectIpHttp: bool,
  securityCheckDirectIpHttps: bool,
  securityCheckIpApiExposed: bool,
  securityCheckWafBypass: bool,
  securityCheckTlsExpiringSoon: bool,
  securityCheckTlsExpiryDays: int,
  securityCheckMissingReferrerPolicy: bool,
  securityCheckMissingPermissionsPolicy: bool,
  securityCheckMissingCoop: bool,
  securityCheckMissingCorp: bool,
  securityCheckMissingCoep: bool,
  securityCheckCacheControlMissing: bool,
  securityCheckLoginNoHttps: bool,
  securityCheckSessionNoSecure: bool,
  securityCheckSessionNoHttponly: bool,
  securityCheckBasicAuthNoTls: bool,
  securityCheckSpfMissing: bool,
  securityCheckDmarcMissing: bool,
  securityCheckDnssecMissing: bool,
  securityCheckZoneTransfer: bool,
  securityCheckAdminPortExposed: bool,
  securityCheckDatabaseExposed: bool,
  securityCheckRedisNoAuth: bool,
  securityCheckKubernetesApiExposed: bool,
  securityCheckSmtpOpenRelay: bool,
  securityCheckCspUnsafeInline: bool,
  securityCheckInsecureFormAction: bool,
  securityCheckNoRateLimiting: bool,
  securityCheckTimeout: int,
  securityCheckMaxWorkers: int,

  // -- OSINT Enrichment --
  osintEnrichmentEnabled: bool,
  shodanEnabled: bool,
  shodanHostLookup: bool,
  shodanReverseDns: bool,
  shodanDomainDns: bool,
  shodanPassiveCves: bool,
  shodanWorkers: int,
  urlscanEnabled: bool,
  urlscanMaxResults: int,
  censysEnabled: bool,
  fofaEnabled: bool,
  fofaMaxResults: int,
  otxEnabled: bool,
  netlasEnabled: bool,
  virusTotalEnabled: bool,
  zoomEyeEnabled: bool,
  zoomEyeMaxResults: int,
  criminalIpEnabled: bool,
  criminalIpWorkers: int,
  uncoverEnabled: bool,
  uncoverMaxResults: int,
  otxWorkers: int,
  virusTotalWorkers: int,
  censysWorkers: int,
  fofaWorkers: int,
  netlasWorkers: int,
  zoomEyeWorkers: int,
}).strip()

export type ReconPresetParams = z.infer<typeof reconPresetSchema>

// ---------------------------------------------------------------------------
// LLM system prompt parameter catalog.
// Embedded in the system message so the LLM knows what keys exist and how to
// set them.  Descriptions are intentionally terse to save tokens.
// ---------------------------------------------------------------------------

export const RECON_PARAMETER_CATALOG = `
## Scan Modules & Global
- scanModules: string[] - Pipeline phases to run. Values: "domain_discovery", "port_scan", "http_probe", "resource_enum", "vuln_scan", "js_recon"
- stealthMode: boolean - Reduce scan aggressiveness and network noise
- updateGraphDb: boolean - Store results in the graph database
- useTorForRecon: boolean - Route traffic through Tor
- useBruteforceForSubdomains: boolean - Enable DNS brute-force for subdomain discovery

## WHOIS & DNS
- whoisEnabled: boolean - Run WHOIS lookups
- whoisMaxRetries: integer - Max WHOIS retries (default 6)
- dnsEnabled: boolean - Run DNS resolution
- dnsMaxRetries: integer - Max DNS retries (default 3)
- dnsMaxWorkers: integer - DNS resolution parallel workers
- dnsRecordParallelism: boolean - Query DNS record types in parallel

## Subdomain Discovery
- subdomainDiscoveryEnabled: boolean - Master switch for subdomain discovery
- crtshEnabled: boolean - Query crt.sh certificate transparency
- crtshMaxResults: integer
- hackerTargetEnabled: boolean - Query HackerTarget
- hackerTargetMaxResults: integer
- knockpyReconEnabled: boolean - Run Knockpy
- knockpyReconMaxResults: integer
- subfinderEnabled: boolean - Run Subfinder
- subfinderMaxResults: integer
- amassEnabled: boolean - Run Amass
- amassMaxResults: integer
- amassTimeout: integer - Amass timeout in seconds
- amassActive: boolean - Amass active probing mode
- amassBrute: boolean - Amass DNS brute-force
- purednsEnabled: boolean - Run PureDNS wildcard filtering
- purednsThreads: integer
- purednsRateLimit: integer
- purednsWildcardBatch: integer - Wildcard filtering batch size
- purednsSkipValidation: boolean

## Port Scanning - Naabu
- naabuEnabled: boolean - Run Naabu port scanner
- naabuTopPorts: string - Top N ports, e.g. "1000"
- naabuCustomPorts: string - Custom port list, e.g. "80,443,8080"
- naabuRateLimit: integer - Packets per second
- naabuThreads: integer
- naabuTimeout: integer - Timeout in milliseconds
- naabuRetries: integer
- naabuScanType: string - "s" (SYN) or "c" (connect)
- naabuExcludeCdn: boolean - Skip CDN IPs
- naabuDisplayCdn: boolean - Show CDN info
- naabuSkipHostDiscovery: boolean
- naabuVerifyPorts: boolean
- naabuPassiveMode: boolean - Use Shodan InternetDB instead of active scan

## Port Scanning - Masscan
- masscanEnabled: boolean - Run Masscan
- masscanTopPorts: string
- masscanCustomPorts: string
- masscanRate: integer - Packets per second
- masscanBanners: boolean - Grab banners
- masscanWait: integer - Wait time in seconds
- masscanRetries: integer
- masscanExcludeTargets: string - Comma-separated targets to exclude

## Port Scanning - Nmap
- nmapEnabled: boolean - Run Nmap service detection
- nmapVersionDetection: boolean - Detect service versions
- nmapScriptScan: boolean - Run NSE vuln scripts
- nmapTimingTemplate: string - "T0" to "T5"
- nmapTimeout: integer - Timeout in seconds
- nmapHostTimeout: integer - Per-host timeout in seconds
- nmapParallelism: integer - IPs scanned concurrently by Nmap

## HTTP Probing - httpx
- httpxEnabled: boolean - Run httpx HTTP prober
- httpxThreads: integer
- httpxTimeout: integer - Seconds
- httpxRetries: integer
- httpxRateLimit: integer - Requests per second
- httpxFollowRedirects: boolean
- httpxMaxRedirects: integer
- httpxProbeStatusCode: boolean
- httpxProbeContentLength: boolean
- httpxProbeContentType: boolean
- httpxProbeTitle: boolean - Extract page title
- httpxProbeServer: boolean - Extract server header
- httpxProbeResponseTime: boolean
- httpxProbeWordCount: boolean
- httpxProbeLineCount: boolean
- httpxProbeTechDetect: boolean - Fingerprint technologies
- httpxProbeIp: boolean
- httpxProbeCname: boolean
- httpxProbeTlsInfo: boolean
- httpxProbeTlsGrab: boolean
- httpxProbeFavicon: boolean
- httpxProbeJarm: boolean - JARM TLS fingerprint
- httpxProbeHash: string - Hash algo: "md5", "sha256", etc.
- httpxIncludeResponse: boolean - Store full response body
- httpxIncludeResponseHeaders: boolean
- httpxProbeAsn: boolean
- httpxProbeCdn: boolean
- httpxPaths: string[] - Additional URL paths to probe
- httpxCustomHeaders: string[] - Custom HTTP headers
- httpxMatchCodes: string[] - Only show responses with these status codes
- httpxFilterCodes: string[] - Hide responses with these status codes

## Technology Fingerprinting - Wappalyzer
- wappalyzerEnabled: boolean
- wappalyzerMinConfidence: integer - 0-100
- wappalyzerRequireHtml: boolean
- wappalyzerAutoUpdate: boolean
- wappalyzerCacheTtlHours: integer

## Banner Grabbing
- bannerGrabEnabled: boolean
- bannerGrabTimeout: integer - Seconds
- bannerGrabThreads: integer
- bannerGrabMaxLength: integer

## Web Crawling - Katana
- katanaEnabled: boolean - Run Katana web crawler
- katanaDepth: integer - Crawl depth
- katanaMaxUrls: integer - Max URLs to crawl
- katanaRateLimit: integer
- katanaTimeout: integer - Seconds
- katanaJsCrawl: boolean - Crawl JS files
- katanaParamsOnly: boolean - Only extract parameterized URLs
- katanaExcludePatterns: string[] - Regex patterns to exclude from crawling
- katanaScope: string - Scope filter: "dn" (domain), "rdn" (root domain), etc.
- katanaCustomHeaders: string[] - Custom HTTP headers for crawler
- katanaParallelism: integer - Targets crawled simultaneously
- katanaConcurrency: integer - Concurrent fetchers per target

## Web Crawling - Hakrawler
- hakrawlerEnabled: boolean
- hakrawlerDepth: integer
- hakrawlerThreads: integer
- hakrawlerTimeout: integer - Seconds
- hakrawlerMaxUrls: integer
- hakrawlerIncludeSubs: boolean - Include subdomains
- hakrawlerInsecure: boolean - Skip TLS verification
- hakrawlerParallelism: integer - Parallel crawler instances

## JavaScript Analysis - jsluice
- jsluiceEnabled: boolean - Run jsluice JS analyzer (active tool, sends HTTP requests)
- jsluiceMaxFiles: integer
- jsluiceTimeout: integer - Seconds
- jsluiceExtractUrls: boolean
- jsluiceExtractSecrets: boolean
- jsluiceConcurrency: integer
- jsluiceParallelism: integer - Base URLs analyzed in parallel

## JavaScript Analysis - JS Recon (deep)
- jsReconEnabled: boolean - Run deep JS analysis
- jsReconMaxFiles: integer
- jsReconTimeout: integer - Seconds
- jsReconConcurrency: integer
- jsReconValidateKeys: boolean - Validate discovered API keys
- jsReconValidationTimeout: integer
- jsReconExtractEndpoints: boolean
- jsReconRegexPatterns: boolean
- jsReconSourceMaps: boolean - Analyze source maps
- jsReconDependencyCheck: boolean
- jsReconDomSinks: boolean - Detect DOM XSS sinks
- jsReconFrameworkDetect: boolean
- jsReconDevComments: boolean - Extract developer comments
- jsReconIncludeChunks: boolean
- jsReconIncludeFrameworkJs: boolean
- jsReconIncludeArchivedJs: boolean
- jsReconMinConfidence: string - "low", "medium", "high"
- jsReconStandaloneCrawlDepth: integer

## Directory Fuzzing - ffuf
- ffufEnabled: boolean - Run ffuf directory fuzzer
- ffufWordlist: string - Path to wordlist file
- ffufThreads: integer
- ffufRate: integer - Requests per second (0 = unlimited)
- ffufTimeout: integer - Seconds
- ffufMaxTime: integer - Max total time in seconds
- ffufMatchCodes: integer[] - HTTP status codes to match, e.g. [200, 301, 403]
- ffufFilterCodes: integer[] - HTTP status codes to filter out
- ffufFilterSize: string - Filter responses by size
- ffufExtensions: string[] - File extensions to fuzz, e.g. [".php", ".asp"]
- ffufRecursion: boolean
- ffufRecursionDepth: integer
- ffufAutoCalibrate: boolean
- ffufFollowRedirects: boolean
- ffufSmartFuzz: boolean
- ffufParallelism: integer - Targets fuzzed in parallel

## Parameter Discovery - Arjun
- arjunEnabled: boolean - Run Arjun parameter discovery
- arjunThreads: integer
- arjunTimeout: integer - Seconds
- arjunScanTimeout: integer - Total scan timeout in seconds
- arjunMethods: string[] - HTTP methods: ["GET", "POST", "PUT", "DELETE", "PATCH"]
- arjunMaxEndpoints: integer
- arjunChunkSize: integer
- arjunRateLimit: integer - Requests per second (0 = unlimited)
- arjunPassive: boolean - Passive mode (no requests)
- arjunStable: boolean - Stability mode (slower but more reliable)
- arjunDisableRedirects: boolean - Disable following redirects

## Passive URL Discovery - GAU
- gauEnabled: boolean - Run GAU (GetAllUrls) archive lookup
- gauProviders: string[] - Sources: "wayback", "commoncrawl", "otx", "urlscan"
- gauMaxUrls: integer
- gauTimeout: integer - Seconds
- gauThreads: integer
- gauBlacklistExtensions: string[] - File extensions to skip, e.g. [".jpg", ".css"]
- gauVerbose: boolean
- gauVerifyUrls: boolean - Verify discovered URLs are alive
- gauDetectMethods: boolean - Detect allowed HTTP methods
- gauFilterDeadEndpoints: boolean
- gauWorkers: integer - Parallel domain query workers

## ParamSpider
- paramspiderEnabled: boolean - Run ParamSpider passive parameter discovery
- paramspiderTimeout: integer - Seconds
- paramspiderWorkers: integer - Parallel domain workers

## API Discovery - Kiterunner
- kiterunnerEnabled: boolean - Run Kiterunner API endpoint discovery
- kiterunnerWordlists: string[] - Wordlists: "routes-small", "routes-large"
- kiterunnerRateLimit: integer
- kiterunnerConnections: integer
- kiterunnerTimeout: integer - Per-request timeout in seconds
- kiterunnerScanTimeout: integer - Total scan timeout in seconds
- kiterunnerThreads: integer
- kiterunnerDetectMethods: boolean
- kiterunnerMethodDetectionMode: string - "bruteforce"
- kiterunnerBruteforceMethods: string[] - ["GET", "POST", "PUT", "DELETE", "PATCH"]
- kiterunnerParallelism: integer - Wordlists processed in parallel

## Vulnerability Scanning - Nuclei
- nucleiEnabled: boolean - Run Nuclei vulnerability scanner
- nucleiSeverity: string[] - Severity filter: "critical", "high", "medium", "low"
- nucleiTemplates: string[] - Specific template paths to include
- nucleiExcludeTemplates: string[] - Template paths to exclude
- nucleiCustomTemplates: string[] - Custom template paths
- nucleiRateLimit: integer - Requests per second
- nucleiBulkSize: integer
- nucleiConcurrency: integer
- nucleiTimeout: integer - Seconds
- nucleiRetries: integer
- nucleiTags: string[] - Template tags to include
- nucleiExcludeTags: string[] - Template tags to exclude, e.g. ["dos", "fuzz"]
- nucleiDastMode: boolean - Dynamic testing mode
- nucleiAutoUpdateTemplates: boolean
- nucleiNewTemplatesOnly: boolean
- nucleiHeadless: boolean - Browser-based testing
- nucleiSystemResolvers: boolean
- nucleiFollowRedirects: boolean
- nucleiMaxRedirects: integer
- nucleiScanAllIps: boolean
- nucleiInteractsh: boolean - Out-of-band interaction detection

## CVE Lookup
- cveLookupEnabled: boolean
- cveLookupSource: string - "nvd"
- cveLookupMaxCves: integer
- cveLookupMinCvss: number - Minimum CVSS score (0-10)

## MITRE CWE/CAPEC Enrichment
- mitreEnabled: boolean
- mitreAutoUpdateDb: boolean
- mitreIncludeCwe: boolean
- mitreIncludeCapec: boolean
- mitreEnrichRecon: boolean
- mitreEnrichGvm: boolean
- mitreCacheTtlHours: integer - Cache time-to-live in hours

## Security Checks
- securityCheckEnabled: boolean - Master switch for passive security checks
- securityCheckDirectIpHttp: boolean - Check direct IP HTTP access
- securityCheckDirectIpHttps: boolean - Check direct IP HTTPS access
- securityCheckIpApiExposed: boolean
- securityCheckWafBypass: boolean
- securityCheckTlsExpiringSoon: boolean
- securityCheckTlsExpiryDays: integer - Days threshold
- securityCheckMissingReferrerPolicy: boolean
- securityCheckMissingPermissionsPolicy: boolean
- securityCheckMissingCoop: boolean
- securityCheckMissingCorp: boolean
- securityCheckMissingCoep: boolean
- securityCheckCacheControlMissing: boolean
- securityCheckLoginNoHttps: boolean
- securityCheckSessionNoSecure: boolean
- securityCheckSessionNoHttponly: boolean
- securityCheckBasicAuthNoTls: boolean
- securityCheckSpfMissing: boolean
- securityCheckDmarcMissing: boolean
- securityCheckDnssecMissing: boolean
- securityCheckZoneTransfer: boolean
- securityCheckAdminPortExposed: boolean
- securityCheckDatabaseExposed: boolean
- securityCheckRedisNoAuth: boolean
- securityCheckKubernetesApiExposed: boolean
- securityCheckSmtpOpenRelay: boolean
- securityCheckCspUnsafeInline: boolean
- securityCheckInsecureFormAction: boolean
- securityCheckNoRateLimiting: boolean
- securityCheckTimeout: integer - Seconds
- securityCheckMaxWorkers: integer

## OSINT & Threat Intelligence
- osintEnrichmentEnabled: boolean - Master switch for OSINT enrichment
- shodanEnabled: boolean - Shodan lookups
- shodanHostLookup: boolean
- shodanReverseDns: boolean
- shodanDomainDns: boolean
- shodanPassiveCves: boolean - Passive CVE lookup via Shodan
- shodanWorkers: integer - Parallel IP lookup workers
- urlscanEnabled: boolean - URLScan.io
- urlscanMaxResults: integer
- censysEnabled: boolean
- fofaEnabled: boolean
- fofaMaxResults: integer
- otxEnabled: boolean - AlienVault OTX
- netlasEnabled: boolean
- virusTotalEnabled: boolean
- zoomEyeEnabled: boolean
- zoomEyeMaxResults: integer
- criminalIpEnabled: boolean
- criminalIpWorkers: integer - Parallel CriminalIP IP enrichment workers
- uncoverEnabled: boolean - ProjectDiscovery Uncover
- uncoverMaxResults: integer
- otxWorkers: integer - Parallel OTX IP enrichment workers
- virusTotalWorkers: integer - Parallel VirusTotal IP enrichment workers
- censysWorkers: integer - Parallel Censys IP enrichment workers
- fofaWorkers: integer - Parallel FOFA IP enrichment workers
- netlasWorkers: integer - Parallel Netlas IP enrichment workers
- zoomEyeWorkers: integer - Parallel ZoomEye IP enrichment workers
`.trim()

// ---------------------------------------------------------------------------
// Helper: extract JSON from a string that may be wrapped in markdown fences.
// ---------------------------------------------------------------------------

export function extractJson(raw: string): string {
  // Try to extract from ```json ... ``` or ``` ... ```
  const fenceMatch = raw.match(/```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/)
  if (fenceMatch) return fenceMatch[1].trim()

  // Try to find the first { ... } block
  const braceStart = raw.indexOf('{')
  const braceEnd = raw.lastIndexOf('}')
  if (braceStart !== -1 && braceEnd > braceStart) {
    return raw.slice(braceStart, braceEnd + 1)
  }

  return raw.trim()
}
