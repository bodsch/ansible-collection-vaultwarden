# python 3 headers, required if submitting to Ansible

# (c) 2022-2024, Bodo Schulz <bodo@boone-schulz.de>
# Apache (see LICENSE or https://opensource.org/licenses/Apache-2.0)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import re

from ansible.utils.display import Display

display = Display()


class FilterModule(object):
    """
    """

    def filters(self):
        return {
            'supported_databases': self.supported_databases,
            'validate_smtp_settings': self.validate_smtp_settings,
            # 'web_vault_directory': self.web_vault_directory,
            'valid_list_data': self.valid_list_data,
        }

    def supported_databases(self, data, distribution, os_family):
        """
        """
        # display.v(f"supported_databases({data}, {distribution}, {os_family})")

        if distribution == "Debian" and (data.startswith("mysql") or data.startswith("postgresql")):
            display.v("""
                The version for Debian based distributions of vaultwarden currently
                only supports one sqlite database!\nPlease change your configuration.""")
            return False

        return True

    def validate_smtp_settings(self, data):
        """
            validate email
        """
        # display.v(f"validate_smtp_settings({data})")
        valid = False
        result_msg = "SMTP Settings are valid."

        smtp_host = data.get("host", None)
        smtp_from = data.get("from", None)
        smtp_use_sendmail = data.get("use_sendmail", None)
        smtp_sendmail_command = data.get("sendmail_command", None)

        if not smtp_host and not smtp_from and not smtp_use_sendmail and not smtp_sendmail_command:
            valid = True
            result_msg = ""
        else:
            if (smtp_host and not smtp_from) or (not smtp_host and smtp_from):
                result_msg = "Both `smtp.host` and `smtp.from` need to be set for email support without `smtp.use_sendmail`."

            if smtp_host and smtp_from:
                """
                    validate sender adress
                """
                valid_smtp_from = re.match(
                    r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$", smtp_from)

                if valid_smtp_from:
                    valid = True
                else:
                    result_msg = "smtp.from does not contain a mandatory @ sign."

            else:
                if smtp_use_sendmail and smtp_sendmail_command:
                    valid = True
                # else:

        result = dict(valid=valid, msg=result_msg)

        # display.v(f"result {result})")

        return result

    # def web_vault_directory(self, data, web_vault_version):
    #     """
    #     """
    #     display.v(f"web_vault_directory({data}, {web_vault_version})")
    #
    #     data = data.replace()

    def valid_list_data(self, data, valid_entries):
        """
        """
        result = []

        if isinstance(data, list):
            data.sort()
            valid_entries.sort()
            result = list(set(data).intersection(valid_entries))
            result.sort()
        # display.v(f"=result: {result}")
        return result
