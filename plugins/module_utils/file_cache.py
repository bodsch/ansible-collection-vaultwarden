# python 3 headers, required if submitting to Ansible

# (c) 2022-2024, Bodo Schulz <bodo@boone-schulz.de>
# Apache (see LICENSE or https://opensource.org/licenses/Apache-2.0)

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import hashlib
import json
import os
import time
from typing import Any


class FileCache:
    """
    Simple TTL-based JSON file cache.

    Each value is persisted as ``{"timestamp": <float>, "value": <payload>}`` in
    a file below ``directory``. The logical name is hashed (SHA-256) to a safe
    filename, so arbitrary names are valid (e.g. ``"index"`` or
    ``"<entry_id>|<field>"``). Entries older than ``ttl`` seconds are treated as
    a miss and removed on access.

    All read/write errors are non-fatal: :meth:`read` returns ``None`` and
    :meth:`write` silently gives up. If a ``display`` object (Ansible's
    ``Display``) is supplied, verbose diagnostics are emitted via ``display.vv``.
    The cached value itself is never logged, so secrets stay out of the logs.
    """

    def __init__(self, directory: str, ttl: int, display: Any | None = None) -> None:
        """
        Args:
            directory: Directory in which cache files are stored. Created if missing.
            ttl: Time-to-live in seconds for cached entries.
            display: Optional Ansible ``Display`` for verbose logging.
        """
        self.directory = directory
        self.ttl = ttl
        self._display = display
        os.makedirs(self.directory, exist_ok=True)

    def _vv(self, message: str) -> None:
        """Emit a verbose message if a display object was provided."""
        if self._display is not None:
            self._display.vv(message)

    def _path(self, name: str) -> str:
        """
        Map a logical cache name to its on-disk file path.

        Args:
            name: Logical cache key (arbitrary string).

        Returns:
            str: Full filesystem path to the cache file for ``name``.
        """
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
        return os.path.join(self.directory, f"{digest}.json")

    def read(self, name: str) -> Any | None:
        """
        Read a cached value if present and not expired.

        Args:
            name: Logical cache key.

        Returns:
            Optional[Any]: The cached value if within TTL, otherwise ``None``.
            Expired entries are removed. On parse/IO errors, returns ``None``.
        """
        path = self._path(name)
        self._vv(f"FileCache::read(name={name}) -> {path}")

        if not os.path.exists(path):
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            age = time.time() - payload["timestamp"]
            if age <= self.ttl:
                return payload["value"]
            os.remove(path)
        except Exception as e:
            self._vv(f"FileCache read error for '{name}': {e}")

        return None

    def write(self, name: str, value: Any) -> None:
        """
        Write a value to the cache.

        Args:
            name: Logical cache key.
            value: JSON-serializable value to cache.

        Notes:
            IO/serialization errors are logged verbosely and ignored. The value
            is intentionally not logged.
        """
        path = self._path(name)
        self._vv(f"FileCache::write(name={name}) -> {path}")

        payload = {"timestamp": time.time(), "value": value}
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f)
        except Exception as e:
            self._vv(f"FileCache write error for '{name}': {e}")
