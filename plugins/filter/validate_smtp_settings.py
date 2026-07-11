# python 3 headers, required if submitting to Ansible

# (c) 2022-2024, Bodo Schulz <bodo@boone-schulz.de>
# Apache (see LICENSE or https://opensource.org/licenses/Apache-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from typing import Dict

from ansible.utils.display import Display

display = Display()

# Precompiled once at import time instead of on every filter invocation.
_SMTP_FROM_RE = re.compile(r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$")


class FilterModule(object):
    """Filter to validate SMTP settings."""

    def filters(self):
        return {
            "validate_smtp_settings": self.validate_smtp_settings,
        }

    def validate_smtp_settings(self, data: Dict) -> Dict:
        """
        Validate SMTP configuration settings.

        Checks that SMTP settings are either:
        1. All empty (no email support configured)
        2. Both host and from address are set (standard SMTP)
        3. Both sendmail flag and sendmail command are set (local sendmail)

        Args:
            data (dict): Dictionary containing SMTP settings with keys:
                - host: SMTP hostname
                - from: Sender email address
                - use_sendmail: Boolean to use sendmail instead of SMTP
                - sendmail_command: Command to use for sendmail

        Returns:
            dict: Dictionary with keys:
                - valid (bool): Whether settings are valid
                - msg (str): Validation message (empty if valid)
        """
        valid = False
        result_msg = "SMTP Settings are valid."

        smtp_host = data.get("host", None)
        smtp_from = data.get("from", None)
        smtp_use_sendmail = data.get("use_sendmail", None)
        smtp_sendmail_command = data.get("sendmail_command", None)

        if (
            not smtp_host
            and not smtp_from
            and not smtp_use_sendmail
            and not smtp_sendmail_command
        ):
            valid = True
            result_msg = ""
        else:
            if (smtp_host and not smtp_from) or (not smtp_host and smtp_from):
                result_msg = "Both `smtp.host` and `smtp.from` need to be set for email support without `smtp.use_sendmail`."

            if smtp_host and smtp_from:
                """
                validate sender adress
                """
                valid_smtp_from = _SMTP_FROM_RE.match(smtp_from)

                if valid_smtp_from:
                    valid = True
                else:
                    result_msg = "smtp.from does not contain a mandatory @ sign."

            else:
                if smtp_use_sendmail and smtp_sendmail_command:
                    valid = True

        result = dict(valid=valid, msg=result_msg)

        return result
