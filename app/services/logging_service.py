"""
Structured Logging Service

Provides JSON-formatted logging with log rotation and a queryable log store
for the Log Viewer UI.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from logging.handlers import RotatingFileHandler
from typing import Any, Deque, Optional

from app.core.clock import utcnow


LOG_DIR = os.getenv("LOG_DIR", "./logs")
MAX_LOG_SIZE = 10 * 1024 * 1024
BACKUP_COUNT = 5
MAX_MEMORY_LOGS = 1000


class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class LogEntry:
    timestamp: str
    level: str
    logger: str
    message: str
    module: Optional[str] = None
    function: Optional[str] = None
    line: Optional[int] = None
    extra: dict[str, Any] = field(default_factory=dict)
    # Monotonic id, assigned when the record is stored. The viewer uses it as a
    # row key and as the "everything after this" cursor, so a refresh appends
    # new lines instead of redrawing the whole list.
    seq: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "level": self.level,
            "logger": self.logger,
            "message": self.message,
            "module": self.module,
            "function": self.function,
            "line": self.line,
            "extra": self.extra,
        }


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": utcnow().isoformat() + "Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if hasattr(record, "extra_data"):
            log_data["extra"] = getattr(record, "extra_data", {})

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


NOISY_LOGGERS = {
    "uvicorn.access",
    "httpx",
    "httpcore",
    "hpack",
    "watchfiles.main",
    "scapy.runtime",
    "scapy.loading",
}

NOISY_MESSAGES = [
    "HTTP/1.1",
    "Started reloader",
    "Started server process",
    "Waiting for application startup",
    "Application startup complete",
    "Shutting down",
    "changes detected",
]


class NoiseFilter(logging.Filter):
    """Filter out routine/noisy log messages from the memory store."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name in NOISY_LOGGERS:
            return False

        if record.levelname == "INFO":
            msg = record.getMessage()
            for pattern in NOISY_MESSAGES:
                if pattern in msg:
                    return False

        return True


class MemoryLogHandler(logging.Handler):
    def __init__(self, max_entries: int = MAX_MEMORY_LOGS):
        super().__init__()
        self.logs: Deque[LogEntry] = deque(maxlen=max_entries)
        self._seq = 0
        self.addFilter(NoiseFilter())

    def emit(self, record: logging.LogRecord) -> None:
        self._seq += 1
        entry = LogEntry(
            timestamp=utcnow().isoformat() + "Z",
            level=record.levelname.lower(),
            logger=record.name,
            message=record.getMessage(),
            module=record.module,
            function=record.funcName,
            line=record.lineno,
            extra=getattr(record, "extra_data", {}),
            seq=self._seq,
        )
        self.logs.append(entry)

    def get_logs(
        self,
        level: Optional[str] = None,
        logger_filter: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        since_seq: Optional[int] = None,
    ) -> list[LogEntry]:
        filtered = list(self.logs)

        # Only entries newer than the caller's cursor: that is what turns a
        # polling refresh into an append instead of a full redraw.
        if since_seq is not None:
            filtered = [log for log in filtered if log.seq > since_seq]

        if level:
            level_lower = level.lower()
            if level_lower == "network":
                filtered = [
                    log for log in filtered
                    if log.logger.startswith(("app.tasks", "app.services", "app.core", "netpulse.plugins"))
                ]
            else:
                filtered = [log for log in filtered if log.level == level_lower]

        if logger_filter:
            filtered = [log for log in filtered if logger_filter in log.logger]

        if search:
            search_lower = search.lower()
            filtered = [
                log for log in filtered
                if search_lower in log.message.lower()
                or (log.module and search_lower in log.module.lower())
            ]

        filtered.reverse()

        return filtered[offset:offset + limit]

    def get_stats(self) -> dict[str, int]:
        stats = {
            "total": len(self.logs),
            "debug": 0,
            "info": 0,
            "warning": 0,
            "error": 0,
            "critical": 0,
        }
        for log in self.logs:
            if log.level in stats:
                stats[log.level] += 1
        return stats

    def clear(self) -> None:
        self.logs.clear()


memory_handler = MemoryLogHandler()


def setup_logging(
    app_name: str = "netpulse",
    log_level: str = "INFO",
    enable_file_logging: bool = True,
) -> None:
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    json_formatter = JSONFormatter()
    console_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    memory_handler.setFormatter(json_formatter)
    root_logger.addHandler(memory_handler)

    if enable_file_logging:
        os.makedirs(LOG_DIR, exist_ok=True)

        app_log_path = os.path.join(LOG_DIR, f"{app_name}.log")
        file_handler = RotatingFileHandler(
            app_log_path,
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT,
        )
        file_handler.setFormatter(json_formatter)
        root_logger.addHandler(file_handler)

        error_log_path = os.path.join(LOG_DIR, f"{app_name}_error.log")
        error_handler = RotatingFileHandler(
            error_log_path,
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT,
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(json_formatter)
        root_logger.addHandler(error_handler)

    # Uvicorn's own loggers must not double up with the root handler: every
    # line used to print twice (once through uvicorn, once through root), which
    # is half of why the console was hard to read. ``propagate = False`` fixes
    # that. Access logs stay out of the console entirely -- one line per HTTP
    # request buried every real message, and the request trail is still
    # available to whoever wants it with --verbose / uvicorn's own options.
    for logger_name in ("uvicorn", "uvicorn.error"):
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.handlers = []
        uvicorn_logger.propagate = False
        uvicorn_logger.addHandler(console_handler)
        uvicorn_logger.addHandler(memory_handler)

    access_logger = logging.getLogger("uvicorn.access")
    access_logger.handlers = []
    access_logger.propagate = False
    access_logger.addHandler(memory_handler)

    # scapy narrates its own environment through its logger, one line at a time:
    # "No route found for IPv4 destination 0.0.0.0 (no default route?)" repeated
    # after every sweep, and the capture-driver banner on every start. None of
    # that is actionable, and it buried the warnings that were. Real scapy
    # errors still come through at ERROR.
    for name in ("scapy.runtime", "scapy.loading"):
        logging.getLogger(name).setLevel(logging.ERROR)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


class StructuredLogger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    def _log(
        self,
        level: int,
        message: str,
        **kwargs: Any,
    ) -> None:
        extra_data = {k: v for k, v in kwargs.items() if v is not None}
        record = self.logger.makeRecord(
            self.logger.name,
            level,
            fn="",
            lno=0,
            msg=message,
            args=(),
            exc_info=None,
        )
        record.extra_data = extra_data
        self.logger.handle(record)

    def debug(self, message: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, message, **kwargs)


def get_structured_logger(name: str) -> StructuredLogger:
    return StructuredLogger(name)
