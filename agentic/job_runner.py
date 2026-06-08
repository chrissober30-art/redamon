"""
Background job runner for long-running tool calls.

JobRegistry holds asyncio Tasks keyed by job_id (uuid4 hex). Each job's stdout
is tee'd to /workspace/<projectId>/jobs/<job_id>.log and metadata sits beside
it as <job_id>.meta.json.

Lifecycle:
    - spawn(): creates meta + log, kicks off asyncio.create_task(_run).
    - _run(): calls a caller-supplied `runner(tool_name, args, append_log)`
      coroutine which executes the tool and appends to the log. On completion
      flips status, writes final meta, emits a job_update WS event.
    - On agent process restart: in-memory state is gone, so recover_on_boot()
      flips any "running" meta on disk to "interrupted".

The 5 fs_*-shaped tools (job_spawn / status / wait / cancel / list) live in
tools.py's in-process dispatch and route directly to this module.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

WORKSPACE_ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace"))


@dataclass
class JobHandle:
    job_id: str
    project_id: str
    tool_name: str
    args: dict
    label: Optional[str]
    status: str  # running|done|failed|cancelled|interrupted
    started_at: str
    ended_at: Optional[str] = None
    exit_code: Optional[int] = None
    output_path: str = ""
    error: Optional[str] = None
    task: Optional[asyncio.Task] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        # Build dict explicitly: asdict() deep-copies every field, which
        # blows up on the live asyncio.Task before we can pop it.
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "task"}


# Runner callable contract:
#   async def runner(tool_name: str, args: dict, append_log: Callable[[str], Awaitable[None]]) -> dict
# Must return {"success": bool, "output": str|None, "error": str|None}.
RunnerFn = Callable[[str, dict, Callable[[str], Awaitable[None]]], Awaitable[dict]]


class JobRegistry:
    def __init__(self):
        self._jobs: dict[str, JobHandle] = {}
        self._lock = asyncio.Lock()
        self._ws_emit: Optional[Callable[[dict], Awaitable[None]]] = None

    def set_ws_emitter(self, fn: Optional[Callable[[dict], Awaitable[None]]]) -> None:
        """Register a coroutine to receive job_update events for the drawer."""
        self._ws_emit = fn

    # ---- path helpers ------------------------------------------------------

    def _jobs_dir(self, project_id: str) -> Path:
        d = WORKSPACE_ROOT / project_id / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _meta_path(self, project_id: str, job_id: str) -> Path:
        return self._jobs_dir(project_id) / f"{job_id}.meta.json"

    def _log_path(self, project_id: str, job_id: str) -> Path:
        return self._jobs_dir(project_id) / f"{job_id}.log"

    def _write_meta(self, handle: JobHandle) -> None:
        try:
            self._meta_path(handle.project_id, handle.job_id).write_text(
                json.dumps(handle.to_dict(), indent=2, default=str)
            )
        except Exception as e:
            logger.error(f"write_meta failed for {handle.job_id}: {e}")

    async def _notify(self, evt: dict) -> None:
        if not self._ws_emit:
            return
        try:
            await self._ws_emit(evt)
        except Exception as e:
            logger.warning(f"job_update emit failed: {e}")

    # ---- public API --------------------------------------------------------

    async def spawn(
        self,
        project_id: str,
        tool_name: str,
        args: dict,
        runner: RunnerFn,
        label: Optional[str] = None,
    ) -> dict:
        """Kick off a background tool execution. Returns synchronously."""
        if not project_id:
            return {"error": "project_id required"}
        job_id = uuid.uuid4().hex
        started = datetime.now(timezone.utc).isoformat()
        log_path = self._log_path(project_id, job_id)
        log_path.touch()

        handle = JobHandle(
            job_id=job_id,
            project_id=project_id,
            tool_name=tool_name,
            args=args or {},
            label=label,
            status="running",
            started_at=started,
            output_path=str(log_path),
        )
        async with self._lock:
            self._jobs[job_id] = handle
        self._write_meta(handle)

        async def append_log(chunk: str) -> None:
            if chunk is None:
                return
            try:
                with log_path.open("a", encoding="utf-8") as f:
                    f.write(chunk)
                    if not chunk.endswith("\n"):
                        f.write("\n")
            except Exception as e:
                logger.error(f"job {job_id} log append failed: {e}")

        async def _run():
            try:
                result = await runner(tool_name, args or {}, append_log)
                if isinstance(result, dict) and result.get("success"):
                    handle.status = "done"
                    handle.exit_code = 0
                else:
                    handle.status = "failed"
                    handle.exit_code = 1
                    if isinstance(result, dict) and result.get("error"):
                        handle.error = str(result["error"])
                final = (result or {}).get("output") if isinstance(result, dict) else result
                if final:
                    txt = final if isinstance(final, str) else str(final)
                    await append_log("\n--- final ---\n")
                    await append_log(txt)
            except asyncio.CancelledError:
                handle.status = "cancelled"
                raise
            except Exception as e:
                handle.status = "failed"
                handle.error = str(e)
                logger.exception(f"job {job_id} crashed")
            finally:
                handle.ended_at = datetime.now(timezone.utc).isoformat()
                handle.task = None
                self._write_meta(handle)
                await self._notify({
                    "type": "job_update",
                    "project_id": project_id,
                    "job_id": job_id,
                    "status": handle.status,
                })

        handle.task = asyncio.create_task(_run())
        await self._notify({
            "type": "job_update",
            "project_id": project_id,
            "job_id": job_id,
            "status": "running",
        })
        return {"job_id": job_id, "output_path": str(log_path), "status": "running"}

    def status(self, project_id: str, job_id: str) -> dict:
        h = self._jobs.get(job_id)
        if not h or h.project_id != project_id:
            mp = self._meta_path(project_id, job_id)
            if mp.exists():
                try:
                    data = json.loads(mp.read_text())
                    data["size_bytes"] = self._log_size(project_id, job_id)
                    data["tail"] = self._log_tail(project_id, job_id, 40)
                    return data
                except Exception as e:
                    return {"error": f"meta unreadable: {e}"}
            return {"error": f"unknown job {job_id}"}
        d = h.to_dict()
        d["size_bytes"] = self._log_size(project_id, job_id)
        d["tail"] = self._log_tail(project_id, job_id, 40)
        return d

    async def wait(self, project_id: str, job_id: str, timeout_sec: float = 30.0) -> dict:
        h = self._jobs.get(job_id)
        if not h or h.project_id != project_id or h.task is None:
            return self.status(project_id, job_id)
        try:
            await asyncio.wait_for(asyncio.shield(h.task), timeout=timeout_sec)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        return self.status(project_id, job_id)

    async def cancel(self, project_id: str, job_id: str) -> dict:
        h = self._jobs.get(job_id)
        if not h or h.project_id != project_id:
            return {"error": f"unknown job {job_id}"}
        if h.task and not h.task.done():
            h.task.cancel()
            try:
                await h.task
            except (asyncio.CancelledError, Exception):
                pass
        return self.status(project_id, job_id)

    def list(self, project_id: str, active: Optional[bool] = None) -> list[dict]:
        rows = [h.to_dict() for h in self._jobs.values() if h.project_id == project_id]
        # Augment from disk so jobs survived across restarts are visible too.
        jobs_dir = WORKSPACE_ROOT / project_id / "jobs"
        if jobs_dir.exists():
            in_mem = {r["job_id"] for r in rows}
            for mp in jobs_dir.glob("*.meta.json"):
                jid = mp.name[:-len(".meta.json")]
                if jid in in_mem:
                    continue
                try:
                    rows.append(json.loads(mp.read_text()))
                except Exception:
                    pass
        if active is True:
            rows = [r for r in rows if r.get("status") == "running"]
        elif active is False:
            rows = [r for r in rows if r.get("status") != "running"]
        rows.sort(key=lambda r: r.get("started_at", ""), reverse=True)
        # Augment with on-disk size/tail snapshot
        for r in rows:
            jid = r.get("job_id")
            if jid:
                r["size_bytes"] = self._log_size(project_id, jid)
        return rows

    # ---- internals ---------------------------------------------------------

    def _log_size(self, project_id: str, job_id: str) -> int:
        try:
            return self._log_path(project_id, job_id).stat().st_size
        except Exception:
            return 0

    def _log_tail(self, project_id: str, job_id: str, n_lines: int) -> str:
        try:
            with self._log_path(project_id, job_id).open("r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            return "".join(lines[-n_lines:])
        except Exception:
            return ""

    def recover_on_boot(self) -> None:
        """Flip any meta files still marked 'running' to 'interrupted'."""
        if not WORKSPACE_ROOT.exists():
            return
        try:
            for project_dir in WORKSPACE_ROOT.iterdir():
                jobs_dir = project_dir / "jobs"
                if not jobs_dir.is_dir():
                    continue
                for mp in jobs_dir.glob("*.meta.json"):
                    try:
                        data = json.loads(mp.read_text())
                        if data.get("status") == "running":
                            data["status"] = "interrupted"
                            data["ended_at"] = datetime.now(timezone.utc).isoformat()
                            mp.write_text(json.dumps(data, indent=2, default=str))
                    except Exception as e:
                        logger.warning(f"recover_on_boot: bad meta {mp}: {e}")
        except Exception as e:
            logger.warning(f"recover_on_boot scan failed: {e}")


# Module-level singleton
_registry: Optional[JobRegistry] = None


def get_registry() -> JobRegistry:
    global _registry
    if _registry is None:
        _registry = JobRegistry()
    return _registry


JOB_TOOL_NAMES = frozenset({
    "job_spawn", "job_status", "job_wait", "job_cancel", "job_list",
})
