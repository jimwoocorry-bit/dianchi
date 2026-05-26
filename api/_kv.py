"""Tiny KV abstraction for Vercel KV / Upstash Redis REST API.

The Vercel "KV" product is Upstash Redis under the hood, so both Vercel-injected
env vars (``KV_REST_API_URL`` / ``KV_REST_API_TOKEN``) and the upstream Upstash
ones (``UPSTASH_REDIS_REST_URL`` / ``UPSTASH_REDIS_REST_TOKEN``) are accepted.

If neither pair is configured, calls fall back to an in-memory dict so local
dev and first-time deploys keep working — the front-end surfaces this with a
"本机临时" badge so nobody mistakes it for durable storage.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from typing import Any


REQUEST_TIMEOUT = 8


def _rest_config() -> tuple[str, str] | None:
    url = (
        os.environ.get("KV_REST_API_URL")
        or os.environ.get("UPSTASH_REDIS_REST_URL")
        or ""
    ).strip().rstrip("/")
    token = (
        os.environ.get("KV_REST_API_TOKEN")
        or os.environ.get("UPSTASH_REDIS_REST_TOKEN")
        or ""
    ).strip()
    if url and token:
        return url, token
    return None


class _MemoryStore:
    """Process-local fallback. Not durable across function invocations."""

    def __init__(self) -> None:
        self._lists: dict[str, list[str]] = {}
        self._values: dict[str, str] = {}
        self._lock = threading.Lock()

    def lpush(self, key: str, value: str) -> None:
        with self._lock:
            self._values.pop(key, None)
            self._lists.setdefault(key, []).insert(0, value)

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        with self._lock:
            items = list(self._lists.get(key, []))
        if stop < 0:
            stop = len(items) + stop
        return items[start : stop + 1]

    def ltrim(self, key: str, start: int, stop: int) -> None:
        with self._lock:
            items = self._lists.get(key, [])
            if stop < 0:
                stop = len(items) + stop
            self._lists[key] = items[start : stop + 1]

    def set_value(self, key: str, value: str) -> None:
        with self._lock:
            self._lists.pop(key, None)
            self._values[key] = value

    def get_value(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._values.get(key, default)


_memory = _MemoryStore()


def _rest_call(command: list[str]) -> Any:
    config = _rest_config()
    if config is None:
        raise RuntimeError("KV REST API not configured")
    url, token = config
    body = json.dumps(command).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def is_persistent() -> bool:
    return _rest_config() is not None


def set_value(key: str, value: str) -> None:
    if is_persistent():
        try:
            _rest_call(["SET", key, value])
            return
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, OSError, ValueError):
            # Fall through to memory store so the user request still succeeds.
            pass
    _memory.set_value(key, value)


def get_value(key: str, default: Any = None) -> Any:
    if is_persistent():
        try:
            result = _rest_call(["GET", key])
            item = result.get("result") if isinstance(result, dict) else result
            if item is None:
                return default
            return str(item)
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, OSError, ValueError):
            pass
    return _memory.get_value(key, default)


def lpush(key: str, value: str) -> None:
    if is_persistent():
        try:
            _rest_call(["LPUSH", key, value])
            return
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, OSError, ValueError):
            # Fall through to memory store so the user request still succeeds.
            pass
    _memory.lpush(key, value)


def lrange(key: str, start: int, stop: int) -> list[str]:
    if is_persistent():
        try:
            result = _rest_call(["LRANGE", key, str(start), str(stop)])
            items = result.get("result") if isinstance(result, dict) else result
            if isinstance(items, list):
                return [str(item) for item in items]
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, OSError, ValueError):
            pass
    return _memory.lrange(key, start, stop)


def ltrim(key: str, start: int, stop: int) -> None:
    if is_persistent():
        try:
            _rest_call(["LTRIM", key, str(start), str(stop)])
            return
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, OSError, ValueError):
            pass
    _memory.ltrim(key, start, stop)
