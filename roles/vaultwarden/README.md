
# Ansible Role:  `vaultwarden`

Ansible role to install and configure vaultwarden on various linux systems.

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-vaultwarden/main.yml?branch=main)][ci]
[![GitHub issues](https://img.shields.io/github/issues/bodsch/ansible-vaultwarden)][issues]
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/bodsch/ansible-vaultwarden)][releases]
[![Ansible Downloads](https://img.shields.io/ansible/role/d/bodsch/vaultwarden?logo=ansible)][galaxy]

[ci]: https://github.com/bodsch/ansible-vaultwarden/actions
[issues]: https://github.com/bodsch/ansible-vaultwarden/issues?q=is%3Aopen+is%3Aissue
[releases]: https://github.com/bodsch/ansible-vaultwarden/releases
[galaxy]: https://galaxy.ansible.com/ui/standalone/roles/bodsch/vaultwarden/


## Requirements & Dependencies

Ansible Collections

- [bodsch.core](https://github.com/bodsch/ansible-collection-core)

```bash
ansible-galaxy collection install bodsch.core
```
or
```bash
ansible-galaxy collection install --requirements-file collections.yml
```

### Operating systems

Tested on

* Arch Linux
* Debian based
    - Debian 12

## configuration

```yaml
vaultwarden_webvault:
  version: 2024.3.1

vaultwarden_cli:
  state: absent
  version: 1.10.1

vaultwarden_service:
  state: started
  enabled: true
  
vaultwarden_config:
  directories:
    data: /var/lib/vaultwarden
    icon_cache: ""                                # data/icon_cache
    attachments: ""                               # data/attachments
    sends: ""                                     # data/sends
    tmp: ""                                       # data/tmp
    templates: ""                                 # data/templates
    web_vault: /usr/share/vaultwarden             # /usr/share/vaultwarden/web-vault/
  templates:
    reload_enabled: false
  web_vault:
    enabled: false
  database:
    url: /var/lib/vaultwarden/db.sqlite3
    enable_db_wal: true
    connection_retries: 15
    timeout: 30
    max_connections: 10
    connection_init: ""
  websocket:
    enabled: false
    address: 0.0.0.0
    port: 3012
  push:
    enabled: false
    installation_id: CHANGEME
    installation_key: CHANGEME
    relay_uri: https://push.bitwarden.com
    identity_uri: https://identity.bitwarden.com
  job:
    job_poll_interval_ms: ""                      # 30000
    send_purge_schedule: ""                       # "0 5 * * * *"
    trash_purge_schedule: ""                      # "0 5 0 * * *"
    incomplete_2fa_schedule: ""                   # "30 * * * * *"
    emergency_notification_reminder_schedule: ""  # "0 3 * * * *"
    emergency_request_timeout_schedule: ""        # "0 7 * * * *"
    event_cleanup_schedule: ""                    # "0 10 0 * * *"
    events_days_retain: ""                        #
    auth_request_purge_schedule: ""               # "30 * * * * *"
  global:
    disable_icon_download: ""                     # false
    domain: ""
    email_change_allowed: ""                      # true
    emergency_access_allowed: ""                  # true
    hibp_api_key: ""
    incomplete_2fa_time_limit: ""                 # 3
    invitation:
      expiration_hours: ""                        # 120
      org_name: ""                                # vaultwarden
    invitations_allowed: ""                       # true
    org:
      attachment_limit: ""
      creation_users: []                          # none / admin1@example.com,admin2@example.com
      events_enabled: ""                          # false
    password:
      hints_allowed: ""                           # true
      iterations: ""                              # 600000
    sends_allowed: true
    show_password_hint: ""                        # false
    signups:
      allowed: ""                                 # true
      domains_whitelist: []                       # example.com,example.net,example.org
      verify: ""                                  # false
      verify_resend:
        limit: ""                                 # 6
        time: ""                                  # 3600
    trash_auto_delete_days: ""                    #
    user:
      attachment_limit: ""    
      send_limit: ""
  logging:
    extended_logging: true
    log_timestamp_format: "%Y-%m-%d %H:%M:%S.%3f"
    use_syslog: false
    log_file: /var/log/vaultwarden/vaultwarden.log
    # Valid values are "trace", "debug", "info", "warn", "error" and "off"
    log_level: info
  smtp:
    host: ""                                      # smtp.domain.tld
    from: ""                                      # vaultwarden@domain.tld
    from_name: ""                                 # vaultwarden
    username: ""                                  # username
    password: ""                                  # password
    timeout: ""                                   # 15
    security: ""                                  # - "starttls": The default port is 587. - "force_tls": The default port is 465.  - "off": The default port is 25.
    port: ""                                      # 587
    use_sendmail: ""                              # false
    sendmail_command: ""                          # "/path/to/sendmail"
    auth_mechanism: []                            # ["Plain", "Login", "Xoauth2"]
    helo_name: "" 
    embed_images: ""                              # true
    debug: ""                                     # false
    accept_invalid_certs: ""                      # false
    accept_invalid_hostnames: ""                  # false
  rocket:
    address: 0.0.0.0
    port: 8000
    tls:                                          # {certs="/path/to/certs.pem",key="/path/to/key.pem"}
      certs: ""
      key: ""
```
## Contribution

Please read [Contribution](CONTRIBUTING.md)

## Development,  Branches (Git Tags)

The `master` Branch is my *Working Horse* includes the "latest, hot shit" and can be complete broken!

If you want to use something stable, please use a [Tagged Version](https://github.com/bodsch/ansible-vaultwarden/tags)!


## Author

- Bodo Schulz

## License

[Apache](LICENSE)

**FREE SOFTWARE, HELL YEAH!**
