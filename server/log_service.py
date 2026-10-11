"""Thread-safe in-memory log capture for the administrator log viewer."""

from collections import Counter, deque
from datetime import datetime, timezone
import logging
import threading
from typing import Optional


class MemoryLogHandler(logging.Handler):
    def __init__(self, capacity: int = 2000):
        super().__init__(level=logging.INFO)
        self._entries = deque(maxlen=capacity)
        self._lock = threading.RLock()

    def emit(self, record: logging.LogRecord):
        try:
            message = record.getMessage()
            if record.exc_info:
                message += "\n" + self.formatException(record.exc_info)
            entry = {
                "timestamp": datetime.fromtimestamp(
                    record.created, tz=timezone.utc
                ).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": message,
            }
            with self._lock:
                self._entries.append(entry)
        except Exception:
            self.handleError(record)

    @staticmethod
    def formatException(exc_info):
        return logging.Formatter().formatException(exc_info)

    def query(
        self,
        limit: int = 250,
        level: Optional[str] = None,
        search: Optional[str] = None,
    ) -> dict:
        with self._lock:
            all_entries = list(self._entries)

        counts = Counter(entry["level"] for entry in all_entries)
        filtered = all_entries
        if level:
            wanted = level.upper()
            accepted = {"ERROR", "CRITICAL"} if wanted == "ERROR" else {wanted}
            filtered = [entry for entry in filtered if entry["level"] in accepted]
        if search:
            needle = search.casefold()
            filtered = [
                entry
                for entry in filtered
                if needle in entry["message"].casefold()
                or needle in entry["logger"].casefold()
            ]

        visible = list(reversed(filtered))[:limit]
        return {
            "entries": visible,
            "matched": len(filtered),
            "stored": len(all_entries),
            "counts": {
                "INFO": counts.get("INFO", 0),
                "WARNING": counts.get("WARNING", 0),
                "ERROR": counts.get("ERROR", 0) + counts.get("CRITICAL", 0),
            },
        }


_handler = MemoryLogHandler()


def install_log_handler():
    root = logging.getLogger()
    if _handler not in root.handlers:
        root.addHandler(_handler)


def get_logs(limit: int = 250, level: Optional[str] = None, search: Optional[str] = None):
    return _handler.query(limit=limit, level=level, search=search)
