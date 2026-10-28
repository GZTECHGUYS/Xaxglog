"""Persistent verification overlay for the declarative module registry.

The registry itself is code/data.  Live-check results are deliberately kept
out of source control in ``data/module_registry_status.json`` so a verified
module stays verified across restarts without pretending that an unverified
candidate is healthy.
"""
from __future__ import annotations

import datetime
import json
import os
import tempfile

import config as C

STATUS_PATH = os.path.join(C.DATA_DIR, "module_registry_status.json")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_status(path=None):
    path = path or STATUS_PATH
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_status(data, path=None):
    """Atomically write the overlay with owner-only permissions."""
    path = path or STATUS_PATH
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".module_registry_", dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        return True
    except OSError:
        return False


def set_status(data, module_id, status, *, query="", checks=0, fragile=False,
               detail="", sample=None):
    """Return a new overlay dict with one module's verification result."""
    out = dict(data or {})
    out[module_id] = {
        "status": status,
        "fragile": bool(fragile),
        "checked_at": _now(),
        "query": query,
        "checks": int(checks or 0),
        "detail": str(detail or "")[:500],
        "sample": sample or [],
    }
    return out
