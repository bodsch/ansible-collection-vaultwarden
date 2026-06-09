# python 3 headers, required if submitting to Ansible

# (c) 2022-2024, Bodo Schulz <bodo@boone-schulz.de>
# Apache (see LICENSE or https://opensource.org/licenses/Apache-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import List

from ansible.utils.display import Display

display = Display()


class FilterModule(object):
    """Filter to validate list data against valid entries."""

    def filters(self):
        return {
            "valid_list_data": self.valid_list_data,
        }

    def valid_list_data(self, data: List, valid_entries: List) -> List:
        """
        Filter a list to only include entries that are in the valid_entries list.

        Returns the intersection of data and valid_entries, sorted alphabetically.

        Args:
            data (list): List of entries to filter
            valid_entries (list): List of valid/allowed entries

        Returns:
            list: Sorted list of valid entries that were in data
        """
        if not isinstance(data, list):
            return []

        return sorted(set(data).intersection(valid_entries))
