from __future__ import absolute_import, division, print_function

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional

from ansible.errors import AnsibleLookupError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()

DOCUMENTATION = """
lookup: rbw
version_added: "1.0.0"
author:
  - "Bodo Schulz (@bodsch) <bodo@boone-schulz.de>"

short_description: Read secrets from Vaultwarden via the rbw CLI
description:
  - This lookup plugin retrieves entries from Vaultwarden using the 'rbw' CLI client.
  - It supports selecting specific fields, optional JSON parsing, and structured error handling.
  - Supports index-based lookups for disambiguation by name/folder/user.

options:
  _terms:
    description:
      - The Vault entry to retrieve, specified by path, name, or UUID.
    required: true
  field:
    description:
      - Optional field within the entry to return (e.g., username, password).
    required: false
    type: str
  parse_json:
    description:
      - If set to true, the returned value will be parsed as JSON.
    required: false
    type: bool
    default: false
  strict_json:
    description:
      - If true and parse_json is enabled, invalid JSON will raise an error.
      - If false, invalid JSON will return an empty dictionary.
    required: false
    type: bool
    default: false
  use_index:
    description:
      - If true, the index will be used to map name/folder/user to a unique id.
    required: false
    type: bool
    default: false
"""

EXAMPLES = """
- name: Read a password from Vault by UUID
  ansible.builtin.debug:
    msg: "{{ lookup('bodsch.vaultwarden.rbw', '0123-uuid-4567', field='password') }}"

- name: Read a password using index
  ansible.builtin.debug:
    msg: "{{ lookup('bodsch.vaultwarden.rbw',
                {'folder': '', 'name': 'ldap'},
                field='password',
                use_index=true
            ) }}"

- name: "read Login (password)"
  ansible.builtin.debug:
    msg: "Password: {{ lookup('bodsch.vaultwarden.rbw', login_entry, field='password') }}"

- name: "Test: JSON parsen"
  ansible.builtin.set_fact:
    json_data: "{{ lookup('bodsch.vaultwarden.rbw', json_entry, parse_json=True) }}"

- name: "Test: Multi fetch"
  ansible.builtin.set_fact:
    multi_data: "{{ lookup('bodsch.vaultwarden.rbw', raw_note, login_entry) }}"


- name: Multi-fetch
  ansible.builtin.set_fact:
    multi: "{{ lookup('bodsch.vaultwarden.rbw',
                    [{'name': 'foo', 'folder': '', 'user': ''}, 'some-uuid'],
                    field='username',
                    use_index=True
            ) }}"
"""

RETURN = """
_raw:
  description:
    - The raw value from the Vault entry, either as a string or dictionary (if parse_json is true).
  type: raw
"""


class LookupModule(LookupBase):
    """
    Ansible lookup plugin to retrieve secrets from Vaultwarden via the `rbw` CLI.

    Capabilities:
      - Fetch a single entry by UUID/name or multiple entries (terms list).
      - Optional selection of a specific field (e.g. username/password) via `rbw get --field`.
      - Optional JSON parsing of fetched values.
      - Optional index-based disambiguation (name + folder + user -> id) using `rbw list`.
      - File-based caching with a TTL to reduce `rbw` invocations.

    Caching:
      - Index cache: `<cache_directory>/index.json`
      - Value cache: `<cache_directory>/<sha256(entry_id|field)>.json`
      - Entries expire after `CACHE_TTL` seconds and are removed automatically on access.
    """

    CACHE_TTL = 600  # 10 Minuten
    cache_directory = f"{Path.home()}/.cache/ansible/lookup/rbw"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Initialize the lookup plugin and ensure the cache directory exists.

        Args:
            *args: Passed through to Ansible's LookupBase.
            **kwargs: Passed through to Ansible's LookupBase.

        Returns:
            None
        """
        super(LookupModule, self).__init__(*args, **kwargs)
        if not os.path.exists(self.cache_directory):
            os.makedirs(self.cache_directory, exist_ok=True)

    def run(
        self, terms: List[Any], variables: Optional[dict] = None, **kwargs: Any
    ) -> List[Any]:
        """
        Execute the lookup.

        Each element in `terms` may be:
          - a string (UUID or entry name)
          - a dict with keys: `name`, `folder`, `user` (used for index-based resolution)

        Keyword Args:
            field (str): Optional field name to fetch from the entry (rbw `--field`).
            parse_json (bool): If True, attempt to parse the fetched value as JSON.
            strict_json (bool): If True and parse_json=True, invalid JSON raises an error;
                otherwise invalid JSON returns `{}`.
            use_index (bool): If True, resolve dict terms via index (rbw list).

        Args:
            terms: A list of requested entries (strings or dicts).
            variables: Ansible variables (unused; kept for LookupBase signature).
            **kwargs: Lookup options described above.

        Returns:
            list[Any]: List of resolved values in the same order as `terms`.
                - If `parse_json` is False: each entry is typically a string.
                - If `parse_json` is True: each entry is a parsed JSON object (dict/list),
                  or `{}` on parse failure when `strict_json` is False.

        Raises:
            AnsibleLookupError: If validation fails, rbw commands fail, index disambiguation fails,
                or JSON parsing fails in strict mode.
        """
        display.vv(f"LookupModule::run(terms={terms}, kwargs={kwargs})")

        if not terms or not isinstance(terms, list) or not terms[0]:
            self._fail("At least one vault entry must be specified.")

        field = kwargs.get("field", "").strip()
        parse_json = kwargs.get("parse_json", False)
        strict_json = kwargs.get("strict_json", False)
        use_index = kwargs.get("use_index", False)

        index_data = None
        if use_index:
            # first sync rbw
            self._sync_rbw()
            index_data = self._read_index()
            if index_data is None:
                index_data = self._fetch_index()
                display.vv(f"Index contains {len(index_data['entries'])} entries.")

        results = []

        for term in terms:
            name, folder, user = ("", "", "")
            if isinstance(term, dict):
                name = term.get("name", "").strip()
                folder = term.get("folder", "").strip()
                user = term.get("user", "").strip()
                raw_entry = f"{name}|{folder}|{user}"
            else:
                name = term.strip()
                raw_entry = name

            if not name:
                continue

            entry_id = name  # fallback: use directly

            if index_data:
                matches = [
                    e
                    for e in index_data["entries"]
                    if e["name"] == name
                    and (not folder or e["folder"] == folder)
                    and (not user or e["user"] == user)
                ]

                if not matches:
                    self._fail(f"No matching entry found in index for: {raw_entry}")

                if len(matches) > 1:
                    self._fail(f"Multiple matches found in index for: {raw_entry}")

                entry_id = matches[0]["id"]
                display.vv(f"Resolved {raw_entry} → id={entry_id}")

            cache_key = self._cache_key(entry_id, field)
            display.vv(f"try to read cache for key {cache_key}.")
            cached = self._read_cache(cache_key)

            if cached is not None:
                value = cached
                display.vv(f"Cache HIT for '{entry_id}'")
            else:
                display.vv(f"Cache MISS for '{entry_id}'")
                value = self._fetch_rbw(entry_id, field)

                # nur wenn das ergebniss ein String ist, in den cache legen.
                if isinstance(value, str):
                    self._write_cache(cache_key, value)

            if parse_json:
                try:
                    results.append(json.loads(value))
                except json.decoder.JSONDecodeError as e:
                    if strict_json:
                        self._fail(
                            f"JSON parsing failed for entry '{entry_id}'",
                            error=str(e),
                        )
                    else:
                        display.vv(
                            f"Warning: Content of '{entry_id}' is not valid JSON."
                        )
                        results.append({})

                except Exception as e:
                    self._fail(f"Unexpected error parsing '{entry_id}'", e)
            else:
                results.append(value)

        return results

    def _sync_rbw(self) -> str:
        """
        Synchronize local `rbw` data with the Vaultwarden server.

        Runs: `rbw sync`

        Returns:
            str: `stdout` from the `rbw sync` command (trimmed).

        Raises:
            AnsibleLookupError: If the `rbw sync` command fails.
        """
        display.vv("LookupModule::_sync_rbw()")

        cmd = ["rbw", "sync"]

        try:
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            display.vv(f"  - stdout: '{stdout}' / stderr: '{stderr}'")

            return stdout

        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() or e.stdout.strip()
            self._fail(
                "Error sync vault entries.",
                cmd=" ".join(cmd),
                error=err_msg,
            )

    def _fetch_rbw(self, entry_id: str, field: str) -> str:
        """
        Fetch a value from Vaultwarden using `rbw get`.

        Command:
          - `rbw get <entry_id>` or
          - `rbw get --field <field> <entry_id>` if `field` is provided.

        Args:
            entry_id: The rbw entry identifier (UUID) or resolvable entry selector.
            field: Optional field name to return (e.g. `username`, `password`).

        Returns:
            str: `stdout` from `rbw get` (trimmed).

        Raises:
            AnsibleLookupError: If the `rbw get` command fails.
        """
        display.vv(f"LookupModule::_fetch_rbw(entry_id={entry_id}, field={field})")

        cmd = ["rbw", "get"]
        if field:
            cmd.extend(["--field", field])
        cmd.append(entry_id)

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
            self._fail(
                "Error retrieving vault entry.",
                entry_id=entry_id,
                cmd=" ".join(cmd),
                error=err_msg,
            )

    def _fetch_index(self) -> Dict[str, Any]:
        """
        Build and cache an index used for disambiguation.

        Runs: `rbw list --fields id,user,name,folder`

        The resulting payload has the structure:
            {
              "timestamp": <float>,
              "entries": [
                {"id": "...", "user": "...", "name": "...", "folder": "..."},
                ...
              ]
            }

        Returns:
            dict[str, Any]: The generated index payload (timestamp + entries).

        Raises:
            AnsibleLookupError: If the `rbw list` command fails.
        """
        display.vv("LookupModule::_fetch_index()")

        cmd = ["rbw", "list", "--fields", "id,user,name,folder"]

        try:
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            lines = [
                line.strip() for line in result.stdout.splitlines() if line.strip()
            ]

            headers = ["id", "user", "name", "folder"]

            entries = []
            for line in lines:
                parts = line.split("\t")
                if len(parts) < len(headers):
                    parts += [""] * (len(headers) - len(parts))
                entry = dict(zip(headers, parts))
                entries.append(entry)

            index_payload = {"timestamp": time.time(), "entries": entries}

            self._write_index(index_payload)
            return index_payload

        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() or e.stdout.strip()
            self._fail(
                "Error retrieving rbw index",
                cmd="rbw list --fields id,user,name,folder",
                error=err_msg,
            )

    def _index_path(self) -> str:
        """
        Get the on-disk path of the index cache file.

        Returns:
            str: Full filesystem path to `index.json` in the cache directory.
        """
        display.vv("LookupModule::_index_path()")

        return os.path.join(self.cache_directory, "index.json")

    def _read_index(self) -> Optional[Dict[str, Any]]:
        """
        Read the cached index if present and not expired.

        Returns:
            Optional[dict[str, Any]]: The cached index payload if available and within TTL,
            otherwise `None`. If expired, the cache file is removed.

        Notes:
            On JSON parse / IO errors, returns `None` and logs a verbose message.
        """
        display.vv("LookupModule::_read_index()")

        path = self._index_path()
        display.vv(f"  - path: {path}")

        if not os.path.exists(path):
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            age = time.time() - payload["timestamp"]
            if age <= self.CACHE_TTL:
                return payload
            else:
                os.remove(path)

        except Exception as e:
            display.vv(f"Index cache read error: {e}")

        return None

    def _write_index(self, index_payload: Dict[str, Any]) -> None:
        """
        Write the index payload to disk.

        Args:
            index_payload: Index payload as generated by :meth:`_fetch_index`.

        Returns:
            None

        Notes:
            IO/serialization errors are logged verbosely and ignored.
        """
        display.vv(f"LookupModule::_write_index(index_payload={index_payload})")

        path = self._index_path()
        display.vv(f"  - path: {path}")

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(index_payload, f)
        except Exception as e:
            display.vv(f"Index cache write error: {e}")

    def _cache_key(self, entry_id: str, field: str) -> str:
        """
        Compute a stable cache key for an entry/field combination.

        Args:
            entry_id: Resolved entry identifier (typically UUID).
            field: Optional field name (may be empty).

        Returns:
            str: SHA-256 hex digest for the key material `"{entry_id}|{field}"`.
        """
        display.vv(f"LookupModule::_cache_key(entry_id={entry_id}, field={field})")

        raw_key = f"{entry_id}|{field}".encode("utf-8")

        return hashlib.sha256(raw_key).hexdigest()

    def _cache_path(self, key: str) -> str:
        """
        Get the on-disk path for a cached value.

        Args:
            key: Cache key as returned by :meth:`_cache_key`.

        Returns:
            str: Full filesystem path to the cache file for the given key.
        """
        display.vv(f"LookupModule::_cache_path(key={key})")

        return os.path.join(self.cache_directory, key + ".json")

    def _read_cache(self, key: str) -> Optional[Any]:
        """
        Read a cached value if present and not expired.

        Args:
            key: Cache key as returned by :meth:`_cache_key`.

        Returns:
            Optional[Any]: Cached value (`payload["value"]`) if within TTL, otherwise `None`.
            If expired, the cache file is removed.

        Notes:
            On JSON parse / IO errors, returns `None` and logs a verbose message.
        """
        display.vv(f"LookupModule::_read_cache(key={key})")

        path = self._cache_path(key)
        display.vv(f"  - path: {path}")

        if not os.path.exists(path):
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            age = time.time() - payload["timestamp"]
            if age <= self.CACHE_TTL:
                return payload["value"]
            else:
                os.remove(path)

        except Exception as e:
            display.vv(f"Cache read error for key {key}: {e}")

        return None

    def _write_cache(self, key: str, value: Any) -> None:
        """
        Write a value to the cache.

        Args:
            key: Cache key as returned by :meth:`_cache_key`.
            value: Value to cache (typically a string).

        Returns:
            None

        Notes:
            IO/serialization errors are logged verbosely and ignored.
        """
        display.vv(f"LookupModule::_write_cache(key={key}, value={value})")

        path = self._cache_path(key)
        payload = {
            "timestamp": time.time(),
            "value": value,
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f)
        except Exception as e:
            display.vv(f"Cache write error for key {key}: {e}")

    def _format_error(self, message: str, **context: Any) -> str:
        """
        Format an error message into a single-line string suitable for Ansible output.

        Args:
            message: Primary error message.
            **context: Optional key/value context to append (e.g. cmd, entry_id, error).

        Returns:
            str: A single-line error string with optional context appended.
        """
        display.vv(f"LookupModule::_format_error(message={message}, context)")

        parts = [message]
        if context:
            details = "; ".join(f"{k} = {v}" for k, v in context.items())
            parts.append(f", {details}")
        return " ".join(parts)

    def _fail(self, message: str, **context: Any) -> NoReturn:
        """
        Raise an AnsibleLookupError with a formatted message.

        Args:
            message: Primary error message.
            **context: Optional key/value context to append (e.g. cmd, entry_id, error).

        Returns:
            NoReturn: This method always raises and never returns.

        Raises:
            AnsibleLookupError: Always raised with the formatted error message.
        """
        display.vv(f"LookupModule::_fail(message={message}, context)")

        full = self._format_error(message, **context)
        # display.error(full)
        # beim Raise nur das Nötigste, damit fatal nur message zeigt
        raise AnsibleLookupError(full)
