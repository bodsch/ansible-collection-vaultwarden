from __future__ import (absolute_import, division, print_function)

import subprocess
import json
import os
import time
import hashlib

from pathlib import Path
from ansible.utils.display import Display
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleLookupError

display = Display()

DOCUMENTATION = """
lookup: rbw
author:
  - Bodo 'bodsch' (@bodsch)
version_added: "1.0.0"
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
  debug:
    msg: "{{ lookup('bodsch.core.rbw', '0123-uuid-4567', field='password') }}"

- name: Read a password using index
  debug:
    msg: "{{ lookup('bodsch.core.rbw',
      {'name': 'expresszuschnitt.de', 'folder': '.immowelt.de', 'user': 'immo@boone-schulz.de'},
      field='password',
      use_index=True) }}"

- name: Multi-fetch
  set_fact:
    multi: "{{ lookup('bodsch.core.rbw',
      [{'name': 'foo', 'folder': '', 'user': ''}, 'some-uuid'],
      field='username',
      use_index=True) }}"
"""

RETURN = """
_raw:
  description:
    - The raw value from the Vault entry, either as a string or dictionary (if parse_json is true).
  type: raw
"""


class LookupModule(LookupBase):
    """
    """

    CACHE_TTL = 600  # 10 Minuten
    cache_directory = f"{Path.home()}/.cache/ansible/lookup/rbw"

    def __init__(self, *args, **kwargs):
        super(LookupModule, self).__init__(*args, **kwargs)
        if not os.path.exists(self.cache_directory):
            os.makedirs(self.cache_directory, exist_ok=True)

    def run(self, terms, variables=None, **kwargs):
        display.vv(f"run(terms={terms}, kwargs={kwargs})")

        if not terms or not isinstance(terms, list) or not terms[0]:
            self._fail("At least one vault entry must be specified.")

        field = kwargs.get("field", "").strip()
        parse_json = kwargs.get("parse_json", False)
        strict_json = kwargs.get("strict_json", False)
        use_index = kwargs.get("use_index", False)

        index_data = None
        if use_index:
            index_data = self._read_index()
            if index_data is None:
                index_data = self._fetch_index()
                display.vv(
                    f"Index contains {len(index_data['entries'])} entries.")

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
                    e for e in index_data["entries"]
                    if e["name"] == name and
                    (not folder or e["folder"] == folder) and
                    (not user or e["user"] == user)
                ]

                if not matches:
                    self._fail(
                        f"No matching entry found in index for: {raw_entry}")

                if len(matches) > 1:
                    self._fail(
                        f"Multiple matches found in index for: {raw_entry}")

                entry_id = matches[0]["id"]
                display.vv(f"Resolved {raw_entry} → id={entry_id}")

            cache_key = self._cache_key(entry_id, field)
            display.vv(f"try to read cache for key {cache_key}")
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
                            f"Warning: Content of '{entry_id}' is not valid JSON.")
                        results.append({})

                except Exception as e:
                    self._fail(f"Unexpected error parsing '{entry_id}'", e)
            else:
                results.append(value)

        return results

    def _fetch_rbw(self, entry_id, field):
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
                "Error retrieving vault entry",
                entry_id=entry_id,
                cmd=" ".join(cmd),
                error=err_msg,
            )

    def _fetch_index(self):
        cmd = ["rbw", "list", "--fields", "id,user,name,folder"]

        try:
            result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            lines = [line.strip()
                     for line in result.stdout.splitlines() if line.strip()]

            headers = ["id", "user", "name", "folder"]

            entries = []
            for line in lines:
                parts = line.split("\t")
                if len(parts) < len(headers):
                    parts += [""] * (len(headers) - len(parts))
                entry = dict(zip(headers, parts))
                entries.append(entry)

            index_payload = {
                "timestamp": time.time(),
                "entries": entries
            }

            self._write_index(index_payload)
            return index_payload

        except subprocess.CalledProcessError as e:
            err_msg = e.stderr.strip() or e.stdout.strip()
            self._fail(
                "Error retrieving rbw index",
                cmd="rbw list --fields id,user,name,folder",
                error=err_msg,
            )

    def _index_path(self):
        return os.path.join(self.cache_directory, "index.json")

    def _read_index(self):
        path = self._index_path()
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

    def _write_index(self, index_payload):
        path = self._index_path()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(index_payload, f)
        except Exception as e:
            display.vv(f"Index cache write error: {e}")

    def _cache_key(self, entry_id, field):
        raw_key = f"{entry_id}|{field}".encode("utf-8")
        return hashlib.sha256(raw_key).hexdigest()

    def _cache_path(self, key):
        return os.path.join(self.cache_directory, key + ".json")

    def _read_cache(self, key):
        path = self._cache_path(key)
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

    def _write_cache(self, key, value):
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

    def _format_error(self, message, **context):
        """
            Format into a single-line block for Ansible's [ERROR] prefix
        """
        parts = [message]
        if context:
            details = "; ".join(f"{k} = {v}" for k, v in context.items())
            parts.append(f", {details}")
        return " ".join(parts)

    def _fail(self, message, **context):
        """
        """
        full = self._format_error(message, **context)
        # display.error(full)
        # beim Raise nur das Nötigste, damit fatal nur message zeigt
        raise AnsibleLookupError(full)
