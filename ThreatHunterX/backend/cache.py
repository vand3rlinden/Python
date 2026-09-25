"""Tiny thread-safe in-memory TTL cache, to cut down on repeat VT calls."""

import threading
import time


class TTLCache:
    def __init__(self, ttl_seconds=300):
        self._ttl = ttl_seconds
        self._store = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._store.get(key)
            if item is None:
                return None
            value, expires_at = item
            if time.time() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key, value):
        with self._lock:
            self._store[key] = (value, time.time() + self._ttl)
