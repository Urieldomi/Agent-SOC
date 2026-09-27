"""Caching boundary for local inventory collection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import Lock

from .collector import LocalInventoryCollector
from .models import InventorySnapshot


class InventoryService:
    """Return recent inventory data while allowing an explicit refresh."""

    def __init__(self, collector: LocalInventoryCollector, cache_seconds: int = 30):
        self.collector = collector
        self.cache_duration = timedelta(seconds=cache_seconds)
        self._snapshot: InventorySnapshot | None = None
        self._cached_at: datetime | None = None
        self._lock = Lock()

    def get_snapshot(self, force: bool = False) -> InventorySnapshot:
        now = datetime.now(timezone.utc)
        with self._lock:
            expired = self._cached_at is None or now - self._cached_at >= self.cache_duration
            if force or self._snapshot is None or expired:
                self._snapshot = self.collector.collect()
                self._cached_at = now
            return self._snapshot
