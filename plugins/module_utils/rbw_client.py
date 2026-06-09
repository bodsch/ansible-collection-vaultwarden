# python 3 headers, required if submitting to Ansible

# (c) 2022-2024, Bodo Schulz <bodo@boone-schulz.de>
# Apache (see LICENSE or https://opensource.org/licenses/Apache-2.0)

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import subprocess
from typing import Any, Sequence


class RbwError(Exception):
    """
    Raised when an ``rbw`` CLI invocation fails.

    Carries the executed command line and the captured error output so callers
    can build their own (e.g. Ansible-specific) error messages without having to
    know how the client shells out.
    """

    def __init__(self, message: str, *, cmd: str = "", error: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.cmd = cmd
        self.error = error


class RbwClient:
    """
    Thin, framework-agnostic wrapper around the ``rbw`` command-line client.

    Each method shells out to ``rbw`` and returns parsed results. On a non-zero
    exit code an :class:`RbwError` is raised (never an Ansible-specific error),
    so this client can be reused and unit-tested independently of Ansible.

    If a ``display`` object (Ansible's ``Display``) is supplied, verbose
    diagnostics are emitted via ``display.vv``. Secret values returned by
    ``rbw get`` are never logged.
    """

    def __init__(self, executable: str = "rbw", display: Any | None = None) -> None:
        """
        Args:
            executable: Name or path of the ``rbw`` binary.
            display: Optional Ansible ``Display`` for verbose logging.
        """
        self._exe = executable
        self._display = display

    def _vv(self, message: str) -> None:
        """Emit a verbose message if a display object was provided."""
        if self._display is not None:
            self._display.vv(message)

    def _run(self, args: Sequence[str]) -> str:
        """
        Run ``rbw`` with the given arguments and return trimmed stdout.

        Args:
            args: Arguments appended to the ``rbw`` executable.

        Returns:
            str: Trimmed ``stdout`` of the command.

        Raises:
            RbwError: If the command exits with a non-zero status.
        """
        cmd = [self._exe, *args]
        self._vv(f"RbwClient::_run(cmd={' '.join(cmd)})")

        try:
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() or e.stdout.strip()
            raise RbwError(
                f"rbw command failed: {' '.join(cmd)}",
                cmd=" ".join(cmd),
                error=err_msg,
            ) from e

    def sync(self) -> str:
        """
        Synchronize local ``rbw`` data with the Vaultwarden server (``rbw sync``).

        Returns:
            str: Trimmed ``stdout`` of the command.

        Raises:
            RbwError: If the command fails.
        """
        return self._run(["sync"])

    def get(self, entry_id: str, field: str = "") -> str:
        """
        Fetch a value via ``rbw get`` (optionally a single ``--field``).

        Args:
            entry_id: The rbw entry identifier (UUID) or resolvable selector.
            field: Optional field name to return (e.g. ``username``, ``password``).

        Returns:
            str: Trimmed ``stdout`` of the command.

        Raises:
            RbwError: If the command fails.
        """
        args = ["get"]
        if field:
            args.extend(["--field", field])
        args.append(entry_id)
        return self._run(args)

    def list_entries(
        self,
        fields: Sequence[str] = ("id", "user", "name", "folder"),
    ) -> list[dict[str, str]]:
        """
        List entries via ``rbw list --fields <fields>``.

        The tab-separated output is parsed into one dict per row, keyed by the
        requested ``fields``. Missing trailing columns are padded with empty
        strings so every dict has all keys.

        Args:
            fields: Field names to request (and the resulting dict keys).

        Returns:
            list[dict[str, str]]: One dict per entry.

        Raises:
            RbwError: If the command fails.
        """
        headers = list(fields)
        output = self._run(["list", "--fields", ",".join(headers)])

        entries: list[dict[str, str]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < len(headers):
                parts += [""] * (len(headers) - len(parts))
            entries.append(dict(zip(headers, parts)))

        return entries
