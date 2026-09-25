"""Readable console view of a RAMShift run (placeholder: passes events through)."""
from __future__ import annotations

import sys
import threading
from typing import Any


class ReadableReporter:
    lock = threading.Lock()

    def __init__(self, mode: str, args: Any = None, stream: Any = None):
        self.mode, self.args, self.stream = mode, args, stream or sys.stdout
        self.context = None

    def emit(self, message: str) -> None:
        with self.lock:
            print(message, file=self.stream, flush=True)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass
