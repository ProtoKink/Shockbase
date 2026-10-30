"""USB serial connection to a PiShock hub."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

from pishock import SerialAPI

if TYPE_CHECKING:
    from shockbase.store import Store

logger = logging.getLogger("shockbase.hub")

RETRY_SECONDS = 2.0


class Hub:
    def __init__(self, port: str | None = None, store: Store | None = None) -> None:
        self.port = port
        self.store = store
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._api: SerialAPI | None = None

    def start(self) -> None:
        """Block until the hub serial port is open, or until stop() runs."""
        self._stop.clear()
        while not self._stop.is_set():
            with self._lock:
                if self._api is not None:
                    return
                try:
                    self._api = SerialAPI(port=self.port)
                except Exception as exc:
                    logger.warning("hub not connected: %s", exc)
                    self._api = None
                else:
                    logger.info("hub connected")
                    return
            self._stop.wait(RETRY_SECONDS)

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            api = self._api
            self._api = None
        if api is None:
            return
        try:
            api.dev.close()
        except Exception as exc:
            logger.warning("hub close failed: %s", exc)
