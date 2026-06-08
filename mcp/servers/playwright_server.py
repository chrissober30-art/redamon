"""
Playwright MCP Server - Browser Automation

Exposes Playwright browser automation as an MCP tool for agentic penetration testing.
Enables JS-rendered content extraction and interactive browser scripting.

Tools:
    - execute_playwright: Extract rendered page content or run Playwright scripts
"""

from fastmcp import FastMCP
import subprocess
import tempfile
import textwrap
import re
import os

# Strip ANSI escape codes (terminal colors) from output
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

# Server configuration
SERVER_NAME = "playwright"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("PLAYWRIGHT_PORT", "8005"))

mcp = FastMCP(SERVER_NAME)


def _run_playwright_script(script: str, timeout: int = 45) -> str:
    """Run a Playwright Python script in a subprocess and return its stdout."""
    script_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, dir='/tmp'
        ) as f:
            f.write(script)
            f.flush()
            script_path = f.name

        result = subprocess.run(
            ['python3', script_path],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = ANSI_ESCAPE.sub('', result.stdout)
        if result.returncode != 0 and result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            # Filter out playwright verbose logging
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line.strip() and not line.strip().startswith('[')
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"

        return output if output.strip() else "[INFO] Script completed with no output"

    except subprocess.TimeoutExpired:
        return f"[ERROR] Script timed out after {timeout} seconds."
    except Exception as e:
        return f"[ERROR] {str(e)}"
    finally:
        if script_path:
            try:
                os.unlink(script_path)
            except OSError:
                pass


# Common Playwright launch args for Docker/root environment
BROWSER_ARGS = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
]

CHROME_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/120.0.0.0 Safari/537.36'
)


@mcp.tool()
def execute_playwright(url: str = "", script: str = "", selector: str = "", format: str = "text") -> str:
    """
    Browser automation tool with two modes: content extraction or custom scripting.

    **Mode 1 — Content extraction** (provide `url`, optionally `selector` and `format`):
    Navigate to a URL with a real browser and extract the rendered content.
    Unlike curl, this fully renders JavaScript — perfect for SPAs and dynamic pages.

    **Mode 2 — Custom script** (provide `script`):
    Run a Playwright Python script for complex multi-step interactions.
    Variables `browser`, `context`, and `page` are pre-initialized.
    Use print() for output.

    Args:
        url: URL to navigate to (Mode 1). Ignored if script is provided.
        script: Python code using Playwright sync API (Mode 2). If provided, url/selector/format are ignored.
        selector: CSS selector to extract specific element (Mode 1, default: entire page body)
        format: "text" for visible text, "html" for inner HTML (Mode 1, default: "text")

    Returns:
        Mode 1: Extracted page content (text or HTML)
        Mode 2: Script stdout (whatever you print())

    Examples:
        Get all visible text from a page:
        - url="http://10.0.0.5:3000"

        Get HTML of a login form:
        - url="http://10.0.0.5/login" selector="form" format="html"

        Login and capture authenticated page:
        - script="page.goto('http://10.0.0.5/login')\\npage.fill('#username', 'admin')\\npage.fill('#password', 'pass')\\npage.click('button[type=submit]')\\npage.wait_for_load_state('networkidle')\\nprint(page.inner_text('body')[:3000])"

        Test XSS in search field:
        - script="page.goto('http://10.0.0.5/search')\\npage.fill('input[name=q]', '<script>alert(1)</script>')\\npage.click('button[type=submit]')\\npage.wait_for_load_state('networkidle')\\nprint(page.content()[:5000])"
    """
    if script.strip():
        return _execute_script_mode(script)
    elif url.strip():
        return _execute_content_mode(url, selector, format)
    else:
        return "[ERROR] Provide either 'url' (content extraction) or 'script' (custom automation)."


def _execute_content_mode(url: str, selector: str, format: str) -> str:
    """Mode 1: Navigate to URL and extract rendered content."""
    use_html = format.lower() == "html"
    max_chars = 40000

    script = textwrap.dedent(f"""\
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args={BROWSER_ARGS!r}
            )
            context = browser.new_context(
                user_agent={CHROME_UA!r},
            )
            page = context.new_page()

            try:
                page.goto({url!r}, wait_until="networkidle", timeout=30000)
            except Exception as e:
                print(f"[ERROR] Navigation failed: {{e}}")
                context.close()
                browser.close()
                raise SystemExit(1)

            try:
                selector = {selector!r}
                use_html = {use_html!r}
                max_chars = {max_chars!r}

                if selector:
                    element = page.query_selector(selector)
                    if not element:
                        print(f"[INFO] No element found matching selector: {{selector}}")
                        raise SystemExit(0)
                    if use_html:
                        content = element.inner_html()
                    else:
                        content = element.inner_text()
                else:
                    if use_html:
                        content = page.content()
                    else:
                        content = page.inner_text("body")

                if len(content) > max_chars:
                    content = content[:max_chars] + "\\n\\n[TRUNCATED - content exceeded " + str(max_chars) + " chars]"

                if content.strip():
                    print(content)
                else:
                    print("[INFO] Page rendered but no content extracted")
            finally:
                context.close()
                browser.close()
    """)

    return _run_playwright_script(script, timeout=45)


_FORBIDDEN_ASYNC_PATTERNS = [
    (re.compile(r'(?<![A-Za-z0-9_])await\s'), 'await'),
    (re.compile(r'(?<![A-Za-z0-9_])asyncio\.run\b'), 'asyncio.run()'),
    (re.compile(r'(?<![A-Za-z0-9_])async\s+def\b'), 'async def'),
    (re.compile(r'(?m)^\s*import\s+asyncio\b'), 'import asyncio'),
    (re.compile(r'(?<![A-Za-z0-9_])async_playwright\b'), 'async_playwright'),
]


# A script that opens its own `sync_playwright()` context is "self-contained":
# it manages the full browser lifecycle itself. Wrapping such a script inside the
# tool's own `with sync_playwright() as p:` block nests two sync contexts, and the
# inner __enter__ aborts with the misleading "Sync API inside the asyncio loop"
# error (the outer context's event loop is already running). Detect this case and
# run the script raw instead of wrapping it.
_SELF_CONTAINED_RE = re.compile(r'(?<![A-Za-z0-9_])sync_playwright\s*\(')

# Preamble for self-contained scripts: force the Docker/root browser args onto every
# launch() call so the agent does not have to remember --no-sandbox (chromium crashes
# as root without it). Patches BrowserType.launch so it works for chromium/firefox/webkit.
_LAUNCH_PATCH = textwrap.dedent(f"""\
    import playwright.sync_api as _pw_sync
    _pw_orig_launch = _pw_sync.BrowserType.launch
    def _pw_patched_launch(self, **kw):
        _args = list(kw.get("args") or [])
        for _a in {BROWSER_ARGS!r}:
            if _a not in _args:
                _args.append(_a)
        kw["args"] = _args
        kw.setdefault("headless", True)
        return _pw_orig_launch(self, **kw)
    _pw_sync.BrowserType.launch = _pw_patched_launch
""")


def _execute_script_mode(user_script: str) -> str:
    """Mode 2: Run arbitrary Playwright Python script with pre-initialized browser."""
    for pattern, name in _FORBIDDEN_ASYNC_PATTERNS:
        if pattern.search(user_script):
            return (
                f"[ERROR] execute_playwright uses Playwright SYNC API. "
                f"Found '{name}' in your script -- remove it. "
                f"Replace 'await page.X(...)' with 'page.X(...)'. "
                f"Replace 'asyncio.sleep(s)' with 'page.wait_for_timeout(s*1000)'. "
                f"Do NOT wrap your code in 'async def' or 'asyncio.run()' -- "
                f"the wrapper already runs inside `with sync_playwright() as p:`."
            )

    # Self-contained script (brings its own `sync_playwright()` context): run it raw
    # so we don't nest two sync contexts. Inject browser args via a launch monkeypatch.
    if _SELF_CONTAINED_RE.search(user_script):
        return _run_playwright_script(_LAUNCH_PATCH + user_script, timeout=60)

    # Build wrapper script with correct indentation
    lines = [
        "from playwright.sync_api import sync_playwright",
        "",
        "with sync_playwright() as p:",
        f"    browser = p.chromium.launch(headless=True, args={BROWSER_ARGS!r})",
        f"    context = browser.new_context(user_agent={CHROME_UA!r}, viewport={{\"width\": 1280, \"height\": 720}})",
        "    page = context.new_page()",
        "    try:",
    ]
    # User script at 8-space indent (inside try: which is inside with:)
    has_code = False
    for line in user_script.splitlines():
        if line.strip():
            lines.append("        " + line)
            has_code = True
        else:
            lines.append("")
    if not has_code:
        lines.append("        pass")
    lines.extend([
        "    finally:",
        "        context.close()",
        "        browser.close()",
    ])
    wrapper = "\n".join(lines) + "\n"

    return _run_playwright_script(wrapper, timeout=60)


if __name__ == "__main__":
    # Check transport mode from environment
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")
