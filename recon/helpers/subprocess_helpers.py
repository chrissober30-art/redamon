"""
Subprocess helpers with progress heartbeat.

The recon pipeline launches blocking subprocesses (Katana, Hakrawler, FFuf,
Kiterunner) via Docker and waits for completion with `subprocess.run`. On
slow targets these calls can run for minutes with no log output, leaving the
recon drawer silent and the user wondering whether the scan hung.

`run_with_heartbeat` is a drop-in replacement for `subprocess.run(...,
capture_output=True)` that emits a periodic "[*][<label>] still running..."
line to stdout while the child is alive. Output goes through the standard
container-stdout path, so it lands in both the global recon SSE stream and
the partial recon SSE stream automatically.
"""
import subprocess
import threading
import time
from typing import List, Optional


def run_with_heartbeat(
    cmd: List[str],
    label: str,
    interval: int = 30,
    timeout: Optional[int] = None,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """
    Run `cmd` and emit a heartbeat every `interval` seconds while it runs.

    Behavior matches `subprocess.run(cmd, capture_output=True, text=text,
    timeout=timeout)` -- same return shape, same TimeoutExpired semantics --
    but with a background thread printing progress so long-running scans
    don't appear hung.

    Args:
        cmd: Command argv (list of strings).
        label: Short tag used in the heartbeat line, e.g. "Katana".
        interval: Seconds between heartbeats. Default 30.
        timeout: Hard timeout in seconds; raises subprocess.TimeoutExpired.
        text: Whether to decode output as text (default True).

    Returns:
        subprocess.CompletedProcess with returncode, stdout, stderr, args.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )

    start = time.monotonic()
    stop = threading.Event()

    def _heartbeat():
        # First tick after `interval` seconds, not immediately.
        while not stop.wait(interval):
            elapsed = int(time.monotonic() - start)
            print(f"[*][{label}] still running... ({elapsed}s elapsed)", flush=True)

    t = threading.Thread(target=_heartbeat, daemon=True)
    t.start()
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Match subprocess.run's behavior: kill the child and re-raise.
        proc.kill()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = "" if text else b"", "" if text else b""
        stop.set()
        t.join(timeout=1)
        raise subprocess.TimeoutExpired(
            cmd, timeout, output=stdout, stderr=stderr
        )
    finally:
        stop.set()
        t.join(timeout=1)

    return subprocess.CompletedProcess(
        args=cmd,
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
    )
