"""Small persistent cache for idempotent HTTP GETs and reusable AI reviews.

POST requests (including RPC writes and DeepSeek calls) are deliberately not cached.
Cache files are local runtime data and should never be committed.
"""
import hashlib
import json
import os
import time
from pathlib import Path


def _root():
    return Path(os.getenv("COINGECKO_CACHE_DIR") or ".cache/coingecko")


def _path(namespace, key):
    payload = json.dumps(
        {"namespace": str(namespace), "key": key},
        sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    safe_namespace = "".join(c for c in str(namespace) if c.isalnum() or c in "-_")[:40] or "cache"
    return _root() / safe_namespace / digest[:2] / (digest + ".json")


def cache_get(namespace, key, ttl_seconds):
    """Return (hit, value). Expired or unreadable entries are treated as misses."""
    if ttl_seconds is None or ttl_seconds <= 0:
        return False, None
    path = _path(namespace, key)
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
        cached_at = float(entry.get("cached_at") or 0)
        if time.time() - cached_at > float(ttl_seconds):
            try:
                path.unlink()
            except OSError:
                pass
            return False, None
        if entry.get("version") != 1 or "value" not in entry:
            return False, None
        return True, entry["value"]
    except (OSError, ValueError, TypeError, AttributeError):
        return False, None


def cache_set(namespace, key, value):
    """Atomically persist JSON-serializable data. Cache failure never breaks a scan."""
    path = _path(namespace, key)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(
                {"version": 1, "cached_at": time.time(), "value": value},
                ensure_ascii=False, separators=(",", ":"), default=str,
            ),
            encoding="utf-8",
        )
        temporary.replace(path)
        return True
    except (OSError, TypeError, ValueError):
        return False


def get_ttl_for_url(url, params=None):
    """Choose conservative TTLs for data that changes at different speeds."""
    url_text = str(url).lower()
    query = {str(k).lower(): str(v).lower() for k, v in (params or {}).items()}
    action = query.get("action", "")

    if "geckoterminal.com" in url_text:
        if "new_pools" in url_text:
            return 180
        if "/tokens/" in url_text or "/pools/" in url_text:
            return 120
        return 300
    if "api.etherscan.io" in url_text:
        if action in {"balance", "tokenbalance"}:
            return 90
        if action in {"getsourcecode", "getcontractcreation"}:
            return 86400
        if action in {"tokeninfo"}:
            return 600
        if action in {"txlist", "txlistinternal"}:
            return 900
        return 300
    if "sourcify.dev" in url_text or "repo.sourcify.dev" in url_text:
        return 86400
    if "api.github.com" in url_text:
        return 900
    if "raw.githubusercontent.com" in url_text:
        return 21600
    if "gopluslabs.io" in url_text:
        return 600
    return 300


def request_cache_key(url, params=None, auth_token=None):
    """Build a key without storing credentials in cache filenames or JSON."""
    token_fingerprint = None
    if auth_token:
        token_fingerprint = hashlib.sha256(str(auth_token).encode("utf-8")).hexdigest()
    return {
        "url": str(url),
        "params": params or {},
        "auth_fingerprint": token_fingerprint,
    }
