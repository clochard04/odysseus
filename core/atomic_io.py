"""Atomic JSON file writes.

Use this everywhere a JSON config file is persisted. A plain `open("w") +
json.dump` truncates the file on first write and only fills it with new
content afterwards — a kill -9 / power loss / OOM in between produces a
truncated or empty file. For password DBs (`auth.json`) and live state
(`sessions.json`, `settings.json`, `integrations.json`, `cookbook_state.json`),
that's a data-loss event.

`atomic_write_json` writes to a sibling tmp file, fsyncs, then `os.replace`s
into place. On POSIX `os.replace` is atomic on the same filesystem.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any, Optional


def _tmp_name(path: str) -> str:
    """Unique temp sibling for `path`.

    PID alone collides when the *same* process writes one file from two
    threads/async tasks concurrently: both open `path.tmp.<pid>`, and the
    second writer's content can overwrite the first's temp file before the
    first `os.replace` runs — silent data loss. Adding a random token makes
    each in-flight write target distinct.
    """
    return f"{path}.tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}"


def atomic_write_json(path: str, data: Any, *, indent: Optional[int] = None) -> None:
    """Atomically persist `data` as JSON at `path`."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = _tmp_name(path)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        # Don't leave a half-written temp sibling behind on failure.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = _tmp_name(path)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
