from __future__ import annotations, unicode_literals

import os

import pytest
import testinfra.utils.ansible_runner
from helper.molecule import get_vars, infra_hosts, local_facts

testinfra_hosts = infra_hosts(host_name="instance")

# --- tests -----------------------------------------------------------------


@pytest.mark.parametrize(
    "dirs",
    [
        "/etc/vaultwarden",
        "/var/lib/vaultwarden",
        "/var/lib/vaultwarden/attachments",
        "/var/lib/vaultwarden/icon_cache",
        "/var/lib/vaultwarden/sends",
        "/var/lib/vaultwarden/tmp",
        "/var/log/vaultwarden",
    ],
)
def test_directories(host, dirs):
    d = host.file(dirs)
    assert d.is_directory


@pytest.mark.parametrize(
    "files",
    [
        "/etc/vaultwarden/config.env",
        "/var/lib/vaultwarden/db.sqlite3",
        "/var/lib/vaultwarden/rsa_key.pem",
        # "/var/lib/vaultwarden/rsa_key.pub.pem",
    ],
)
def test_files(host, files):
    f = host.file(files)
    assert f.is_file


def test_service_running_and_enabled(host, get_vars):
    """
    running service
    """
    service_name = "vaultwarden"

    service = host.service(service_name)
    assert service.is_running
    assert service.is_enabled


def test_listening_socket(host, get_vars):
    """ """
    listening = host.socket.get_listening_sockets()

    for i in listening:
        print(i)

    listen = []
    listen.append("tcp://127.0.0.1:8000")

    for spec in listen:
        socket = host.socket(spec)
        assert socket.is_listening
