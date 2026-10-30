"""Run the Shockbase server."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from shockbase.app import create_app
from shockbase.hub import Hub
from shockbase.store import Store

HOST = "127.0.0.1"
PORT = 9837
DB_PATH = Path("data") / "shockbase.db"


def serial_port() -> str | None:
    """Device from SHOCKBASE_PORT. Unset or blank means USB autodetect."""
    raw = os.environ.get("SHOCKBASE_PORT", "").strip()
    return raw or None


def main() -> None:
    """Bind 127.0.0.1:9837 and open the hub on SHOCKBASE_PORT or autodetect.

    ``Store.ensure_owner`` returns the generated password while the owner has
    not kept or replaced it, and ``None`` after that choice.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    store = Store(DB_PATH)
    password = store.ensure_owner()
    if password:
        print(f"Owner password: {password}")
    hub = Hub(port=serial_port(), store=store)
    uvicorn.run(create_app(store, hub), host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
