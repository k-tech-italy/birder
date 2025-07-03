from unittest.mock import Mock

import paramiko
import pytest

from birder.checks.ssh import SSHCheck
from birder.exceptions import CheckError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_valid_rsa_private_key_pem():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_bytes.decode('utf-8')


def test_ssh():
    c = SSHCheck(configuration={"server": "localhost", "username": "test"})
    assert c.config == {
        "login_timeout": 2,
        "server": "localhost",
        "password": "",
        "port": 22,
        "username": "test",
        "ssh_key": ""
    }


def test_check_success(monkeypatch):
    mock_ssh_client = Mock()
    mock_ssh_client.return_value.connect = Mock()
    mock_ssh_client.return_value.close = Mock()
    monkeypatch.setattr("paramiko.SSHClient", mock_ssh_client)
    c = SSHCheck(configuration={"server": "localhost", "database": "test"})
    assert c.check()


def test_check_fail(monkeypatch):
    mock_ssh_client = Mock()
    mock_ssh_client.return_value.connect.side_effect = paramiko.AuthenticationException("Authentication failed")
    monkeypatch.setattr("paramiko.SSHClient", mock_ssh_client)
    c = SSHCheck(configuration={"server": "localhost"})
    assert not c.check()
    with pytest.raises(CheckError):
        assert c.check(True)


def test_ssh_with_valid_key(monkeypatch):
    key_pem = generate_valid_rsa_private_key_pem()
    mock_client = Mock()
    mock_client.return_value.connect = Mock()
    mock_client.return_value.exec_command.return_value = (Mock(), Mock(), Mock())
    mock_client.return_value.exec_command.return_value[1].read.return_value = b'SSH connection test\n'
    mock_client.return_value.exec_command.return_value[2].read.return_value = b''
    mock_client.return_value.close = Mock()
    monkeypatch.setattr("paramiko.SSHClient", mock_client)

    c = SSHCheck(configuration={
        "server": "localhost",
        "username": "test",
        "ssh_key": key_pem,
    })
    assert c.check(raise_error=True)
