# Ansible Collection - bodsch.vaultwarden

A collection of Ansible roles for Vaultwarden and Tools.


[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-collection-vaultwarden/main.yml?branch=main)][ci]
[![GitHub issues](https://img.shields.io/github/issues/bodsch/ansible-collection-vaultwarden)][issues]
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/bodsch/ansible-collection-vaultwarden)][releases]

[ci]: https://github.com/bodsch/ansible-collection-vaultwarden/actions
[issues]: https://github.com/bodsch/ansible-collection-vaultwarden/issues?q=is%3Aopen+is%3Aissue
[releases]: https://github.com/bodsch/ansible-collection-vaultwarden/releases


## supported operating systems

* Arch Linux
* Debian based
    - Debian 11 / 12
    - Ubuntu 22.04 / 24.04

## Contribution

Please read [Contribution](CONTRIBUTING.md)

## Development,  Branches (Git Tags)

The `master` Branch is my *Working Horse* includes the "latest, hot shit" and can be complete broken!

If you want to use something stable, please use a [Tagged Version](https://github.com/bodsch/ansible-collection-vaultwarden/tags)!

---

## Roles

| Role                                                        | Build State | Description |
|:----------------------------------------------------------- | :---- | :---- |
| [bodsch.vaultwarden.vaultwarden](./roles/vaultwarden/README.md) | [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-collection-vaultwarden/vaultwarden.yml?branch=main)][vaultwarden]   | Ansible role to install and configure `vaultwarden`. |
| [bodsch.vaultwarden.rbw](./roles/rbw/README.md)                 | [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/bodsch/ansible-collection-vaultwarden/rbw.yml?branch=main)][rbw]                   | Ansible role to install and configure `rbw`. |


[vaultwarden]: https://github.com/bodsch/ansible-collection-vaultwarden/actions/workflows/vaultwarden.yml
[rbw]: https://github.com/bodsch/ansible-collection-vaultwarden/actions/workflows/rbw.yml


### Modules

| Name                      | Description |
|:--------------------------|:----|


### Filter

| Name                      | Description |
|:--------------------------|:----|
| `bodsch.vaultwarden.supported_databases`     | Checks whether the configured database type is supported |
| `bodsch.vaultwarden.validate_smtp_settings`  | Validates the SMTP settings. |
| `bodsch.vaultwarden.valid_list_data`         | Validates configuration parameters. |


### Lookup

| Name                      | Description |
|:--------------------------|:----|
| `bodsch.vaultwarden.rbw`  | Reads credentials from a Vaultwarden. |

#### `bodsch.vaultwarden.rbw`

Requires an installed and configured [rbw binary](https://github.com/doy/rbw).

The lookup plugin creates a cache directory below `${HOME}/.cache/ansible/lookup/rbw` to reduce requests against a Vaultwarden.  
The cache is valid for 10 minutes per entry.

**No credentials are stored, only how the entries can be accessed.**


#### usage 

Examples can be found under [tests](tests/test_lookup.yml).

## Author

- Bodo Schulz

## License

[Apache](LICENSE)

**FREE SOFTWARE, HELL YEAH!**
