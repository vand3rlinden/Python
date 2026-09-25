"""Sliding-window rate limiter guarding outbound calls to VirusTotal, so the
app self-throttles to the free-tier limit instead of relying only on VT's
own 429 responses."""

import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self, max_calls=4, period_seconds=60):
        self._max_calls = max_calls
        self._period = period_seconds
        self._calls = deque()
        self._lock = threading.Lock()

    def allow(self):
        """Returns (allowed: bool, retry_after_seconds: int)."""
        now = time.time()
        with self._lock:
            while self._calls and now - self._calls[0] > self._period:
                self._calls.popleft()

            if len(self._calls) >= self._max_calls:
                retry_after = self._period - (now - self._calls[0])
                return False, max(1, int(retry_after) + 1)

            self._calls.append(now)
            return True, 0
