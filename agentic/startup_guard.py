"""Startup-time invariants for the agent process.

The agent's fireteam confirmation registry
(``orchestrator_helpers/fireteam_confirmation_registry.py``) tracks pending
operator-approval state in a module-level Python dict — process-local, with
no shared backing store. That design is correct for a single-process
deployment (asyncio cooperative scheduling makes dict ops between awaits
atomic) but silently breaks under multiple workers: registrations in worker
A are invisible to worker B, confirmations route to a worker that has no
pending entry, and members hang on ``entry.event.wait()`` until cancelled.

``check_single_worker()`` refuses to start the process if any well-known
worker-count env var indicates more than one worker. The alternative
remediation (move the registry to a shared backing store like Redis or
Postgres LISTEN/NOTIFY) is out of scope for this guard.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


# Env vars that operators commonly use to declare worker counts. Covers
# uvicorn-explicit (UVICORN_WORKERS), gunicorn convention (WEB_CONCURRENCY),
# gunicorn-explicit (GUNICORN_WORKERS), and a generic project convention
# (WORKERS).
_WORKER_ENV_VARS: tuple[str, ...] = (
    "WORKERS",
    "UVICORN_WORKERS",
    "WEB_CONCURRENCY",
    "GUNICORN_WORKERS",
)


def check_single_worker() -> None:
    """Raise RuntimeError if any worker-count env var declares more than one
    worker. Call from the FastAPI lifespan before any orchestrator init.

    Malformed env values (non-integer) are tolerated as "unset" so a typo
    doesn't induce a denial-of-startup.

    Known limitation: a bare ``uvicorn --workers N`` CLI invocation that
    doesn't also set one of the env vars is not detected. Operators changing
    the deployment to multi-worker should set ``WORKERS=N`` to declare
    intent; this guard then fires.
    """
    for var in _WORKER_ENV_VARS:
        raw = os.environ.get(var)
        if raw is None:
            continue
        try:
            workers = int(raw)
        except (ValueError, TypeError):
            continue
        if workers > 1:
            msg = (
                f"FATAL: agent registry is in-process; refusing to start with "
                f"{var}={workers}. Either set {var}=1, or replace the in-process "
                f"registry at orchestrator_helpers/fireteam_confirmation_registry.py "
                f"with a shared backing store (Redis, Postgres LISTEN/NOTIFY, etc.)."
            )
            logger.critical(msg)
            raise RuntimeError(msg)
