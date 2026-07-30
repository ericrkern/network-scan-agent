"""Crontab read/write and scan job control for the Network Pulse dashboard."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
LOCK_DIR = LOG_DIR / ".cron-locks"

CRON_JOBS: dict[str, dict[str, Any]] = {
    "ping": {
        "id": "ping",
        "label": "Ping Scan",
        "description": "Quick discovery and online/offline refresh (no per-host deep nmap).",
        "script": BASE_DIR / "scripts" / "cron-quick-scan.sh",
        "log": LOG_DIR / "cron-quick.log",
        "lock": LOCK_DIR / "ping.lock",
        "default_schedule": "*/15 * * * *",
        "script_marker": "cron-quick-scan.sh",
        "schedule_presets": [
            {"label": "Every 5 minutes", "value": "*/5 * * * *"},
            {"label": "Every 15 minutes", "value": "*/15 * * * *"},
            {"label": "Every 30 minutes", "value": "*/30 * * * *"},
            {"label": "Every hour", "value": "0 * * * *"},
        ],
    },
    "deep": {
        "id": "deep",
        "label": "Deep Scan",
        "description": "Full nmap deep inspection for known hosts.",
        "script": BASE_DIR / "scripts" / "cron-deep-scan.sh",
        "log": LOG_DIR / "cron-deep.log",
        "lock": LOCK_DIR / "deep.lock",
        "default_schedule": "10 * * * *",
        "script_marker": "cron-deep-scan.sh",
        "schedule_presets": [
            {"label": "Every hour at :10", "value": "10 * * * *"},
            {"label": "Every 2 hours at :10", "value": "10 */2 * * *"},
            {"label": "Every 6 hours at :10", "value": "10 */6 * * *"},
            {"label": "Daily at 03:10", "value": "10 3 * * *"},
        ],
    },
}

SCHEDULE_RE = re.compile(r"^(\S+\s+){4}\S+$")
CRON_HEADER = """SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
"""


def _job(job_id: str) -> dict[str, Any]:
    job = CRON_JOBS.get(job_id)
    if not job:
        raise KeyError(job_id)
    return job


def read_crontab_text() -> str:
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as e:
        return f"# crontab unavailable: {e}\n"
    if result.returncode != 0:
        err = (result.stderr or "").strip().lower()
        if "no crontab" in err:
            return ""
        return ""
    return result.stdout or ""


def _parse_crontab_lines(text: str) -> tuple[list[str], list[str], dict[str, str]]:
    """Return (header_lines, other_lines, job_id -> schedule) for managed jobs."""
    header: list[str] = []
    other: list[str] = []
    schedules: dict[str, str] = {}

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            other.append(line)
            continue
        if stripped.startswith("#"):
            other.append(line)
            continue
        if stripped.startswith(("SHELL=", "PATH=", "MAILTO=", "HOME=")):
            header.append(line)
            continue

        parts = stripped.split()
        if len(parts) < 6:
            other.append(line)
            continue

        schedule = " ".join(parts[:5])
        command = " ".join(parts[5:])
        matched = False
        for job_id, meta in CRON_JOBS.items():
            marker = str(meta["script_marker"])
            if marker in command:
                schedules[job_id] = schedule
                matched = True
                break
        if not matched:
            other.append(line)

    return header, other, schedules


def _build_crontab_text(schedules: dict[str, str]) -> str:
    header, other, _existing = _parse_crontab_lines(read_crontab_text())
    if not header:
        header = [ln for ln in CRON_HEADER.strip().splitlines()]

    lines: list[str] = list(header)
    if lines and lines[-1].strip():
        lines.append("")

    for job_id, meta in CRON_JOBS.items():
        schedule = schedules.get(job_id)
        if not schedule:
            continue
        script = meta["script"]
        log = meta["log"]
        lines.append(
            f"{schedule} {script} >> {log} 2>&1"
        )

    if other:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend(other)

    body = "\n".join(lines).strip()
    return (body + "\n") if body else ""


def install_crontab(schedules: dict[str, str]) -> tuple[bool, str]:
    if not _validate_schedules(schedules):
        return False, "Invalid cron schedule expression."

    for job_id in schedules:
        script = _job(job_id)["script"]
        if not script.is_file():
            return False, f"Missing script for {job_id}: {script}"

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    for meta in CRON_JOBS.values():
        script = meta["script"]
        if script.is_file():
            script.chmod(script.stat().st_mode | 0o111)

    text = _build_crontab_text(schedules)
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".crontab") as tmp:
            tmp.write(text)
            tmp_path = tmp.name
        result = subprocess.run(
            ["crontab", tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        os.unlink(tmp_path)
    except Exception as e:
        return False, f"Failed to install crontab: {e}"

    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "crontab rejected the file").strip()
    return True, "Crontab updated."


def _validate_schedules(schedules: dict[str, str]) -> bool:
    for schedule in schedules.values():
        if not schedule or not SCHEDULE_RE.match(schedule.strip()):
            return False
    return True


def _is_process_running(marker: str) -> bool:
    try:
        result = subprocess.run(
            ["pgrep", "-f", marker],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0 and bool((result.stdout or "").strip())
    except Exception:
        return False


def _lock_active(lock_path: Path) -> bool:
    if not lock_path.is_file():
        return False
    try:
        with open(lock_path, "r") as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, ValueError, PermissionError, OSError):
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def tail_log(path: Path, lines: int = 12) -> list[str]:
    if not path.is_file():
        return []
    try:
        with open(path, "r", errors="replace") as f:
            content = f.readlines()
        return [ln.rstrip("\n") for ln in content[-max(1, lines) :]]
    except OSError:
        return []


def log_mtime(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        return None


def get_jobs_status() -> dict[str, Any]:
    _, _, schedules = _parse_crontab_lines(read_crontab_text())
    jobs = []
    for job_id, meta in CRON_JOBS.items():
        schedule = schedules.get(job_id)
        marker = str(meta["script_marker"])
        running = _lock_active(meta["lock"]) or _is_process_running(marker)
        jobs.append({
            "id": job_id,
            "label": meta["label"],
            "description": meta["description"],
            "enabled": schedule is not None,
            "schedule": schedule,
            "default_schedule": meta["default_schedule"],
            "schedule_presets": meta["schedule_presets"],
            "running": running,
            "script": str(meta["script"]),
            "log": str(meta["log"]),
            "log_tail": tail_log(meta["log"]),
            "log_updated_at": log_mtime(meta["log"]),
        })
    return {
        "ok": True,
        "jobs": jobs,
        "crontab_installed": bool(schedules),
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def set_job_enabled(job_id: str, enabled: bool, schedule: str | None = None) -> tuple[bool, str]:
    meta = _job(job_id)
    _, _, schedules = _parse_crontab_lines(read_crontab_text())

    if enabled:
        schedules[job_id] = (schedule or schedules.get(job_id) or meta["default_schedule"]).strip()
    elif job_id in schedules:
        del schedules[job_id]

    return install_crontab(schedules)


def set_job_schedule(job_id: str, schedule: str) -> tuple[bool, str]:
    meta = _job(job_id)
    schedule = schedule.strip()
    if not SCHEDULE_RE.match(schedule):
        return False, "Invalid cron schedule (expected 5 fields)."

    _, _, schedules = _parse_crontab_lines(read_crontab_text())
    if job_id not in schedules:
        schedules[job_id] = schedule
    else:
        schedules[job_id] = schedule
    return install_crontab(schedules)


def run_job_now(job_id: str) -> tuple[bool, str, int | None]:
    meta = _job(job_id)
    script = meta["script"]
    lock_path = meta["lock"]
    log_path = meta["log"]

    if not script.is_file():
        return False, f"Script not found: {script}", None

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOCK_DIR.mkdir(parents=True, exist_ok=True)

    if _lock_active(lock_path) or _is_process_running(str(meta["script_marker"])):
        return False, f"{meta['label']} is already running.", None

    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a") as log_f:
        log_f.write(
            f"\n--- manual run {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ({job_id}) ---\n"
        )
        proc = subprocess.Popen(
            ["/bin/bash", str(script)],
            cwd=str(BASE_DIR),
            stdout=log_f,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    try:
        lock_path.write_text(str(proc.pid))
    except OSError:
        pass

    return True, f"{meta['label']} started (PID {proc.pid}).", proc.pid
