# python 3 headers, required if submitting to Ansible

# (c) 2022-2024, Bodo Schulz <bodo@boone-schulz.de>
# Apache (see LICENSE or https://opensource.org/licenses/Apache-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.utils.display import Display

display = Display()


class FilterModule(object):
    """Filter to validate if a database is supported for a distribution."""

    def filters(self):
        return {
            "supported_databases": self.supported_databases,
        }

    def supported_databases(self, data: str, distribution: str, os_family: str) -> bool:
        """
        Check if the specified database is supported for the given distribution.

        Some distributions like Debian don't support MySQL or PostgreSQL backends
        and only support SQLite.

        Args:
            data (str): Database type (e.g., 'mysql', 'postgresql', 'sqlite')
            distribution (str): The Linux distribution (e.g., 'Debian', 'ArchLinux')
            os_family (str): The OS family (kept for signature compatibility, currently unused)

        Returns:
            bool: True if database is supported, False otherwise
        """
        if distribution == "Debian" and data.startswith(("mysql", "postgresql")):
            display.v(
                """
                The version for Debian based distributions of vaultwarden currently
                only supports one sqlite database!\nPlease change your configuration."""
            )
            return False

        return True
