"""
RedAmon - jsluice Helpers for Resource Enumeration
===================================================
JavaScript analysis using jsluice to extract URLs, paths, and secrets.
jsluice is compiled into the recon container (no Docker image needed).
"""

import json
import os
import shutil
import ssl
import subprocess
import urllib.request
import uuid
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


DEFAULT_JSLUICE_EXCLUDE_PATTERNS = [
    '/_next/image', '/_next/static', '/_next/data', '/__nextjs',
    '/_nuxt/', '/__nuxt',
    '/runtime.', '/polyfills.', '/vendor.',
    '/webpack', '/chunk.', '.chunk.js', '.bundle.js', 'hot-update',
    '/static/', '/public/', '/dist/', '/build/', '/lib/', '/vendor/', '/node_modules/',
    '.js', '.mjs', '.map', '.css', '.scss', '.sass', '.less',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.avif',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '/rxjs/', '/react/', '/angular/', '/lodash/', '/zone.js/',
]


def _split_exclude_patterns(exclude_patterns: List[str]) -> Tuple[List[str], List[str]]:
    """
    Split deny-list patterns into (extension suffixes, substring patterns).

    Extensions are matched against the path suffix only (e.g. `.js` matches
    `/app/main.js` but not `/api/users.json`). Everything else uses substring
    match against the URL path + query.
    """
    extensions = []
    substrings = []
    for raw in exclude_patterns:
        if not raw:
            continue
        pat = raw.lower()
        # An extension pattern starts with '.' and contains no slash.
        if pat.startswith('.') and '/' not in pat:
            extensions.append(pat)
        else:
            substrings.append(pat)
    return extensions, substrings


def _create_temp_dir(prefix: str = "jsluice_verify") -> Path:
    """Create a temp directory under /tmp/redamon for Docker-in-Docker compatibility."""
    temp_dir = Path(f"/tmp/redamon/.{prefix}_{uuid.uuid4().hex[:8]}")
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir


def _cleanup_temp_dir(temp_dir: Path):
    """Clean up a temp directory."""
    try:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    except Exception:
        pass


def filter_jsluice_url(url: str, exclude_patterns: List[str]) -> bool:
    """
    Return True when a jsluice URL should be probed.

    jsluice often extracts library, bundle, sourcemap, and static asset paths
    from JavaScript source. These are filtered before HTTP validation to avoid
    spending probe budget on obvious non-application endpoints.
    """
    if not url:
        return False

    try:
        parsed = urlparse(url)
        path_lower = (parsed.path or "").lower()
        query_lower = (parsed.query or "").lower()
        haystack = f"{path_lower} {query_lower}"

        extensions, substrings = _split_exclude_patterns(exclude_patterns)

        # Extensions match the path suffix only — `.js` must not drop `.json`.
        if any(path_lower.endswith(ext) for ext in extensions):
            return False

        if any(sub in haystack for sub in substrings):
            return False

        return True
    except Exception:
        return False


def verify_jsluice_urls(
    urls: List[str],
    docker_image: str,
    threads: int,
    timeout: int,
    rate_limit: int,
    accept_status: List[int],
    exclude_patterns: List[str] = None,
    use_proxy: bool = False,
) -> Tuple[Set[str], Dict[str, int]]:
    """
    Verify jsluice-discovered URLs are live using httpx.

    This verifier fails closed: if probing fails or times out, unverified
    jsluice URLs are not returned for graph publication.
    """
    exclude_patterns = exclude_patterns or []
    stats = {
        "jsluice_verify_total": len(urls),
        "jsluice_verify_candidates": 0,
        "jsluice_skipped_blacklist": 0,
        "jsluice_verified": 0,
        "jsluice_skipped_unverified": 0,
    }

    if not urls:
        return set(), stats

    candidates = []
    for url in sorted(set(urls)):
        if filter_jsluice_url(url, exclude_patterns):
            candidates.append(url)
        else:
            stats["jsluice_skipped_blacklist"] += 1

    stats["jsluice_verify_candidates"] = len(candidates)
    if not candidates:
        stats["jsluice_skipped_unverified"] = 0
        print(f"[*][jsluice] Verification skipped: all {len(urls)} URLs matched noise filters")
        return set(), stats

    print(f"\n[*][jsluice] Verifying {len(candidates)} jsluice URLs...")
    if stats["jsluice_skipped_blacklist"]:
        print(f"[*][jsluice] Skipped {stats['jsluice_skipped_blacklist']} URLs via noise filters")

    temp_dir = _create_temp_dir("jsluice_verify")
    try:
        urls_file = temp_dir / "urls.txt"
        output_file = temp_dir / "verified.json"

        with open(urls_file, 'w') as f:
            for url in candidates:
                f.write(f"{url}\n")

        # --net=host is ALWAYS passed so the httpx verifier can reach loopback /
        # local-lab targets. See recon/helpers/resource_enum/katana_helpers.py
        # for the long comment on sibling-container network isolation.
        cmd = [
            "docker", "run", "--rm", "--net=host",
            "-v", f"{temp_dir}:/data",
            docker_image,
            "-l", "/data/urls.txt",
            "-o", "/data/verified.json",
            "-json",
            "-silent",
            "-nc",
            "-t", str(threads),
            "-timeout", str(timeout),
            "-rl", str(rate_limit),
        ]

        if use_proxy:
            cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            print("[!][jsluice] URL verification timeout; dropping unverified jsluice URLs")
            stats["jsluice_skipped_unverified"] = len(candidates)
            return set(), stats
        except Exception as e:
            print(f"[!][jsluice] URL verification error: {e}; dropping unverified jsluice URLs")
            stats["jsluice_skipped_unverified"] = len(candidates)
            return set(), stats

        if proc.returncode != 0:
            stderr_tail = (proc.stderr or "").strip().splitlines()[-3:]
            print(
                f"[!][jsluice] httpx exited with code {proc.returncode}; "
                f"dropping unverified jsluice URLs. stderr: {' | '.join(stderr_tail)}"
            )
            stats["jsluice_skipped_unverified"] = len(candidates)
            return set(), stats

        verified = set()
        accept_codes = {int(code) for code in accept_status}

        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                    except json.JSONDecodeError:
                        continue

                    url = entry.get('url', '')
                    status = entry.get('status_code') or entry.get('status-code')
                    try:
                        status = int(status)
                    except (TypeError, ValueError):
                        continue

                    if url and status in accept_codes:
                        verified.add(url)

        stats["jsluice_verified"] = len(verified)
        stats["jsluice_skipped_unverified"] = len(candidates) - len(verified)
        print(f"[+][jsluice] Verified: {len(verified)}/{len(candidates)} URLs are live")
        return verified, stats
    finally:
        _cleanup_temp_dir(temp_dir)


def _extract_urls_for_base(base_url, file_entries, concurrency, timeout, allowed_hosts):
    """Extract URLs from JS files for a single base URL."""
    extracted_urls = []
    external_domains = []
    filepaths = [fp for _, fp in file_entries]
    extracted = _run_jsluice_urls(filepaths, base_url, concurrency, timeout)
    for entry in extracted:
        raw_url = entry.get("url", "")
        if not raw_url:
            continue

        resolved = _resolve_url(raw_url, base_url)
        if not resolved:
            continue

        try:
            parsed = urlparse(resolved)
            host = parsed.hostname or ''
            if host and allowed_hosts and host not in allowed_hosts:
                external_domains.append({
                    "domain": host, "source": "jsluice", "url": resolved,
                })
                continue
        except Exception:
            continue

        extracted_urls.append(resolved)

    return extracted_urls, external_domains


def _extract_secrets_for_base(base_url, file_entries, concurrency, timeout):
    """Extract secrets from JS files for a single base URL."""
    filepaths = [fp for _, fp in file_entries]
    secrets = _run_jsluice_secrets(filepaths, concurrency, timeout)
    for secret in secrets:
        secret["base_url"] = base_url
    return secrets


def run_jsluice_analysis(
    discovered_urls: List[str],
    max_files: int,
    timeout: int,
    extract_urls: bool,
    extract_secrets: bool,
    concurrency: int,
    parallelism: int = 3,
    allowed_hosts: set = None,
    use_proxy: bool = False
) -> Dict:
    """
    Analyze JavaScript files with jsluice to extract URLs, endpoints, and secrets.

    Downloads JS files already discovered by Katana/Hakrawler and analyzes
    their contents. Sends HTTP requests to the target to fetch each JS file.

    Args:
        discovered_urls: All URLs discovered by crawlers (filtered to .js)
        max_files: Maximum number of JS files to analyze
        timeout: Overall timeout in seconds
        extract_urls: Whether to run jsluice urls mode
        extract_secrets: Whether to run jsluice secrets mode
        concurrency: Number of files to process concurrently
        allowed_hosts: Set of hostnames for scope filtering
        use_proxy: Whether to use Tor proxy

    Returns:
        Dict with urls, secrets, and external_domains
    """
    if not shutil.which('jsluice'):
        print("[!][jsluice] jsluice binary not found in PATH, skipping")
        return {"urls": [], "secrets": [], "external_domains": []}

    js_urls = [u for u in discovered_urls if _is_js_url(u)]
    if not js_urls:
        print("[-][jsluice] No JavaScript files found in discovered URLs")
        return {"urls": [], "secrets": [], "external_domains": []}

    js_urls = js_urls[:max_files]
    print(f"\n[*][jsluice] Analyzing {len(js_urls)} JavaScript files...")

    work_dir = Path(f"/tmp/redamon/jsluice_{os.getpid()}")
    work_dir.mkdir(parents=True, exist_ok=True)

    result = {"urls": [], "secrets": [], "external_domains": []}

    try:
        downloaded = _download_js_files(js_urls, work_dir, use_proxy)
        if not downloaded:
            print("[-][jsluice] No JS files downloaded successfully")
            return result

        print(f"[+][jsluice] Downloaded {len(downloaded)} JS files")

        files_by_base = {}
        filepath_to_source_url = {filepath: url for url, filepath in downloaded.items()}
        for url, filepath in downloaded.items():
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base not in files_by_base:
                files_by_base[base] = []
            files_by_base[base].append((url, filepath))

        all_extracted_urls = []
        all_secrets = []
        external_domains = []

        if extract_urls:
            max_workers = min(parallelism, len(files_by_base))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_extract_urls_for_base, base_url, file_entries, concurrency, timeout, allowed_hosts): base_url
                    for base_url, file_entries in files_by_base.items()
                }
                for future in as_completed(futures):
                    try:
                        urls, externals = future.result()
                        all_extracted_urls.extend(urls)
                        external_domains.extend(externals)
                    except Exception as e:
                        print(f"[!][jsluice] Error: {e}")

            print(f"[+][jsluice] Extracted {len(all_extracted_urls)} in-scope URLs from JS")
            if external_domains:
                print(f"[+][jsluice] Filtered {len(external_domains)} out-of-scope URLs")

        if extract_secrets:
            max_workers = min(parallelism, len(files_by_base))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_extract_secrets_for_base, base_url, file_entries, concurrency, timeout): base_url
                    for base_url, file_entries in files_by_base.items()
                }
                for future in as_completed(futures):
                    try:
                        secrets = future.result()
                        for secret in secrets:
                            filename = secret.get("filename", "")
                            secret["source_url"] = filepath_to_source_url.get(filename, "")
                        all_secrets.extend(secrets)
                    except Exception as e:
                        print(f"[!][jsluice] Error: {e}")

            if all_secrets:
                print(f"[+][jsluice] Found {len(all_secrets)} potential secrets in JS files")
                for s in all_secrets[:5]:
                    print(f"[+][jsluice]   {s.get('kind', 'unknown')}: severity={s.get('severity', 'info')}")
                if len(all_secrets) > 5:
                    print(f"[+][jsluice]   ... and {len(all_secrets) - 5} more")

        result["urls"] = sorted(set(all_extracted_urls))
        result["secrets"] = all_secrets
        result["external_domains"] = external_domains

    finally:
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)

    return result


def merge_jsluice_into_by_base_url(
    jsluice_urls: List[str],
    existing_by_base_url: Dict,
) -> Tuple[Dict, Dict]:
    """
    Merge jsluice-extracted URLs into the existing by_base_url structure.

    Args:
        jsluice_urls: URLs extracted by jsluice
        existing_by_base_url: Existing by_base_url structure

    Returns:
        Tuple of (merged by_base_url, stats dict)
    """
    from .classification import classify_endpoint, classify_parameter, infer_parameter_type

    stats = {
        "jsluice_total": len(jsluice_urls),
        "jsluice_parsed": 0,
        "jsluice_new": 0,
        "jsluice_overlap": 0,
    }

    for url in jsluice_urls:
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path or "/"
            methods = ["GET"]

            stats["jsluice_parsed"] += 1

            if base_url in existing_by_base_url:
                existing_endpoints = existing_by_base_url[base_url].get('endpoints', {})
                if path in existing_endpoints:
                    stats["jsluice_overlap"] += 1
                    existing_ep = existing_endpoints[path]
                    sources = existing_ep.get('sources', [])
                    if 'jsluice' not in sources:
                        sources.append('jsluice')
                        existing_ep['sources'] = sources
                    continue

            stats["jsluice_new"] += 1

            query_param_list = []
            if parsed.query:
                for param_pair in parsed.query.split('&'):
                    if '=' in param_pair:
                        pname, pval = param_pair.split('=', 1)
                        if pname:
                            sample_vals = [pval] if pval else []
                            query_param_list.append({
                                "name": pname,
                                "sample_values": sample_vals,
                                "type": infer_parameter_type(pname, sample_vals),
                                "category": classify_parameter(pname),
                                "position": "query",
                            })

            category = classify_endpoint(path, methods, {"query": query_param_list, "body": [], "path": []})

            endpoint = {
                "path": path,
                "methods": methods,
                "full_url": url,
                "has_parameters": bool(query_param_list),
                "category": category,
                "sources": ["jsluice"],
                "parameters": {"query": query_param_list, "body": [], "path": []},
                "parameter_count": {
                    "query": len(query_param_list),
                    "body": 0,
                    "path": 0,
                    "total": len(query_param_list),
                },
                "sample_urls": [url],
                "urls_found": 1,
            }

            if base_url not in existing_by_base_url:
                existing_by_base_url[base_url] = {
                    'base_url': base_url,
                    'endpoints': {},
                    'summary': {
                        'total_endpoints': 0,
                        'total_parameters': 0,
                        'methods': {},
                        'categories': {},
                    }
                }

            existing_by_base_url[base_url]['endpoints'][path] = endpoint
            summary = existing_by_base_url[base_url]['summary']
            summary['total_endpoints'] = len(existing_by_base_url[base_url]['endpoints'])
            for m in methods:
                summary['methods'][m] = summary['methods'].get(m, 0) + 1
            summary['categories'][category] = summary['categories'].get(category, 0) + 1
            summary['total_parameters'] += len(query_param_list)

        except Exception:
            continue

    return existing_by_base_url, stats


def _is_js_url(url: str) -> bool:
    """Check if a URL points to a JavaScript file."""
    try:
        parsed = urlparse(url)
        path = parsed.path.lower().split('?')[0]
        return path.endswith('.js') or path.endswith('.mjs')
    except Exception:
        return False


def _download_js_files(
    js_urls: List[str],
    work_dir: Path,
    use_proxy: bool,
) -> Dict[str, str]:
    """Download JavaScript files to a local directory."""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    if use_proxy:
        proxy_handler = urllib.request.ProxyHandler({
            'http': 'socks5://127.0.0.1:9050',
            'https': 'socks5://127.0.0.1:9050'
        })
        opener = urllib.request.build_opener(
            proxy_handler, urllib.request.HTTPSHandler(context=ssl_context)
        )
    else:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl_context)
        )

    downloaded = {}
    for i, url in enumerate(js_urls):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': '*/*',
                }
            )
            response = opener.open(request, timeout=10)

            # Skip non-200 responses (redirects, 404s, etc.)
            if response.status != 200:
                print(f"[-][jsluice] Skipping {url}: HTTP {response.status}")
                continue

            # Verify response is actually JavaScript, not an HTML error page
            content_type = response.headers.get('Content-Type', '').lower()
            if 'html' in content_type and 'javascript' not in content_type:
                print(f"[-][jsluice] Skipping {url}: Content-Type is {content_type} (not JS)")
                continue

            content = response.read()

            if len(content) > 10 * 1024 * 1024:
                continue

            filepath = str(work_dir / f"js_{i}.js")
            with open(filepath, 'wb') as f:
                f.write(content)
            downloaded[url] = filepath
        except Exception as e:
            print(f"[!][jsluice] Failed to download {url}: {e}")
            continue

    return downloaded


def _run_jsluice_urls(
    filepaths: List[str],
    base_url: str,
    concurrency: int,
    timeout: int,
) -> List[Dict]:
    """Run jsluice urls mode on downloaded JS files."""
    cmd = [
        "jsluice", "urls",
        "--resolve-paths", base_url,
        "--concurrency", str(concurrency),
    ] + filepaths

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        entries = []
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return entries
    except subprocess.TimeoutExpired:
        print(f"[!][jsluice] URL extraction timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"[!][jsluice] URL extraction error: {e}")
        return []


def _run_jsluice_secrets(
    filepaths: List[str],
    concurrency: int,
    timeout: int,
) -> List[Dict]:
    """Run jsluice secrets mode on downloaded JS files."""
    cmd = [
        "jsluice", "secrets",
        "--concurrency", str(concurrency),
    ] + filepaths

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        entries = []
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return entries
    except subprocess.TimeoutExpired:
        print(f"[!][jsluice] Secret extraction timed out after {timeout}s")
        return []
    except Exception as e:
        print(f"[!][jsluice] Secret extraction error: {e}")
        return []


def _resolve_url(raw_url: str, base_url: str) -> str:
    """Resolve a potentially relative URL against a base URL."""
    if raw_url.startswith(('http://', 'https://')):
        return raw_url

    if raw_url.startswith('//'):
        parsed_base = urlparse(base_url)
        return f"{parsed_base.scheme}:{raw_url}"

    if raw_url.startswith('/'):
        parsed_base = urlparse(base_url)
        return f"{parsed_base.scheme}://{parsed_base.netloc}{raw_url}"

    placeholder = "EXPR"
    if placeholder in raw_url:
        return ""

    return urljoin(base_url, raw_url)
