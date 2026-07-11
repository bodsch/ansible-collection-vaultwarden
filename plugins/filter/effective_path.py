# python 3 headers, required if submitting to Ansible

# (c) 2022-2024, Bodo Schulz <bodo@boone-schulz.de>
# Apache (see LICENSE or https://opensource.org/licenses/Apache-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
from pathlib import Path
from typing import Dict, List, Optional, Union

from ansible.utils.display import Display

display = Display()


class FilterModule(object):
    """Filter to compute effective absolute paths for vaultwarden directories."""

    def filters(self):
        return {
            "effective_path": self.effective_path,
        }

    def effective_path(
        self,
        data: Union[Dict, str],
        config: Union[str, Dict],
    ) -> Optional[Union[List[Path], Path]]:
        """
        Compute effective absolute target paths.

        Handles two use cases:
        1. If data is a dict and config is a string (base path):
           Returns list of absolute paths for all directory entries.
           Relative paths are resolved relative to config base path.

        2. If data is a string and config is a dict:
           Returns single absolute path for the data directory.
           Uses config.directories.data as base for relative paths.

        Args:
            data: Either dict of directories or string path
            config: Either string base path or dict with configuration

        Returns:
            list: List of Path objects (case 1)
            Path: Single Path object (case 2)
            None: If data is empty or invalid
        """

        def _expand(p: str) -> str:
            return os.path.expandvars(os.path.expanduser(p))

        if isinstance(data, dict) and isinstance(config, str):
            result: List[Path] = []
            data_base = Path(config)
            _data = data.copy()

            _data.pop("data", None)
            _data.pop("web_vault", None)

            dirs = [x for _, x in _data.items() if x.strip()]

            for d in dirs:
                p = Path(_expand(d))
                if p.is_absolute():
                    result.append(p)
                else:
                    result.append((data_base / p).resolve(strict=False))

            return result

        elif isinstance(data, str) and isinstance(config, dict):
            _data = config.get("directories", {}).get("data", "")
            data_base = Path(_expand(_data), "")
            raw = (data or "").strip()

            if not raw:
                return None

            p = Path(_expand(raw))
            if p.is_absolute():
                return p

            # relativ => relativ zu data
            return (data_base / p).resolve(strict=False)

        return None
