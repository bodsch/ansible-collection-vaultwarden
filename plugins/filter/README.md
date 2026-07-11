# Vaultwarden Ansible Filter Plugins

Dokumentation für die Ansible Filter der Vaultwarden Collection.

## Übersicht

Diese Collection stellt folgende Ansible Filter zur Verfügung:

| Filter | Beschreibung | Datei |
|--------|-------------|-------|
| `supported_databases` | Validiert Datenbankunterstützung für eine Distribution | `supported_databases.py` |
| `validate_smtp_settings` | Validiert SMTP Email-Konfiguration | `validate_smtp_settings.py` |
| `valid_list_data` | Filtert Liste gegen gültige Einträge | `valid_list_data.py` |
| `effective_path` | Berechnet effektive absolute Zielpfade | `effective_path.py` |

## Filter Details

### 1. supported_databases

**Zweck:** Validiert, ob eine bestimmte Datenbank-Backend für eine Linux-Distribution unterstützt wird.

**Anwendung:**
```yaml
supported: "{{ 'mysql' | vaultwarden.rbw.supported_databases('Debian', 'Debian') }}"
```

**Einschränkungen:**
- Debian-basierte Distributionen unterstützen derzeit nur SQLite
- MySQL und PostgreSQL werden auf Debian nicht unterstützt

Siehe [DOCUMENTATION_supported_databases.yml](DOCUMENTATION_supported_databases.yml) für detaillierte Dokumentation.

### 2. validate_smtp_settings

**Zweck:** Validiert SMTP Email-Konfiguration für Vaultwarden.

**Anwendung:**
```yaml
smtp_result: "{{ smtp_config | vaultwarden.rbw.validate_smtp_settings }}"
```

**Gültige Konfigurationen:**
1. Leer (keine Email-Unterstützung)
2. SMTP: `host` + `from` beide gesetzt
3. Sendmail: `use_sendmail` + `sendmail_command` beide gesetzt

Siehe [DOCUMENTATION_validate_smtp_settings.yml](DOCUMENTATION_validate_smtp_settings.yml) für detaillierte Dokumentation.

### 3. valid_list_data

**Zweck:** Filtert eine Liste, um nur gültige Einträge beizubehalten.

**Anwendung:**
```yaml
filtered_list: "{{ my_list | vaultwarden.rbw.valid_list_data(allowed_entries) }}"
```

**Verhalten:**
- Berechnet die Schnittmenge von Eingabeliste und gültigen Einträgen
- Beide Listen werden alphabetisch sortiert
- Duplikate werden entfernt
- Ergebnis ist sortiert

Siehe [DOCUMENTATION_valid_list_data.yml](DOCUMENTATION_valid_list_data.yml) für detaillierte Dokumentation.

### 4. effective_path

**Zweck:** Berechnet effektive absolute Zielpfade für Vaultwarden-Verzeichnisse.

**Anwendung:**
```yaml
# Mode 1: Dict → List of Paths
paths: "{{ dir_dict | vaultwarden.rbw.effective_path(base_path) }}"

# Mode 2: String → Single Path
path: "{{ single_dir | vaultwarden.rbw.effective_path(config_dict) }}"
```

**Verhalten:**
- Relative Pfade werden relativ zur konfigurierten Basis aufgelöst
- Absolute Pfade werden unverändert zurückgegeben
- Unterstützt Umgebungsvariablen (`$VAR`) und Home-Verzeichnis (`~`) Expansion

Siehe [DOCUMENTATION_effective_path.yml](DOCUMENTATION_effective_path.yml) für detaillierte Dokumentation.

## Verwendungsbeispiele

### Beispiel 1: Datenbankvalidierung

```yaml
- name: Validate database backend for distribution
  hosts: all
  tasks:
    - name: Check if configured database is supported
      ansible.builtin.assert:
        that:
          - database_type | vaultwarden.rbw.supported_databases(ansible_distribution, ansible_os_family)
        fail_msg: "Database {{ database_type }} is not supported on {{ ansible_distribution }}"
      vars:
        database_type: "mysql"
```

### Beispiel 2: SMTP Validierung

```yaml
- name: Validate SMTP settings
  hosts: all
  tasks:
    - name: Validate email configuration
      ansible.builtin.assert:
        that:
          - smtp_validation.valid
        fail_msg: "{{ smtp_validation.msg }}"
      vars:
        smtp_validation: "{{ vaultwarden_smtp | vaultwarden.rbw.validate_smtp_settings }}"
```

### Beispiel 3: List Filtering

```yaml
- name: Filter list against valid entries
  hosts: all
  tasks:
    - name: Keep only valid features
      ansible.builtin.set_fact:
        enabled_features: "{{ requested_features | vaultwarden.rbw.valid_list_data(supported_features) }}"
```

### Beispiel 4: Path Resolution

```yaml
- name: Resolve paths
  hosts: all
  tasks:
    - name: Get effective paths for all data directories
      ansible.builtin.set_fact:
        vaultwarden_paths: "{{ vaultwarden_dirs | vaultwarden.rbw.effective_path('/var/lib/vaultwarden') }}"
      vars:
        vaultwarden_dirs:
          attachments: "attachments"
          icons: "web/vault/icons"
          send: "send"
```

## Technische Details

### Datestruktur

```
plugins/filter/
├── effective_path.py
├── supported_databases.py
├── validate_smtp_settings.py
├── valid_list_data.py
├── DOCUMENTATION_effective_path.yml
├── DOCUMENTATION_supported_databases.yml
├── DOCUMENTATION_validate_smtp_settings.yml
└── DOCUMENTATION_valid_list_data.yml
```

### Abhängigkeiten

- Python 3.6+
- Ansible 2.9+

### Lizenz

Apache License 2.0

Siehe [LICENSE](../LICENSE) für Details.

## Copyright

Copyright (c) 2022-2024, Bodo Schulz <bodo@boone-schulz.de>
