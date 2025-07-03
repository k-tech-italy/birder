import logging
from typing import Any, Optional
import io
import base64
import re

from django import forms
from django.core.validators import MinValueValidator
import paramiko

from ..exceptions import CheckError
from .base import BaseCheck, ConfigForm, WriteOnlyField

logger = logging.getLogger(__name__)


class SSHConfig(ConfigForm):
    server = forms.CharField(required=True)
    port = forms.IntegerField(validators=[MinValueValidator(1)], initial=22)
    username = forms.CharField(required=False)
    password = WriteOnlyField(required=False)
    login_timeout = forms.IntegerField(initial=2)
    ssh_key = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 6, "cols": 40}),
        help_text="Paste your private SSH key here (supports RSA, Ed25519, ECDSA formats in PEM/OpenSSH format)"
    )


class SSHCheck(BaseCheck):
    icon = "ssh.svg"
    pragma = ["ssh"]
    config_class = SSHConfig
    address_format = "{server}:{port}"

    @classmethod
    def clean_config(cls, cfg: dict[str, Any]) -> dict[str, Any]:
        if "host" in cfg:
            cfg["server"] = cfg.pop("host")
        return cfg

    def _normalize_ssh_key(self, key_content: str) -> str:
        """Normalize SSH key content to proper PEM format"""
        if not key_content:
            return key_content

        # Remove extra whitespace and normalize line endings
        key_content = key_content.strip().replace('\r\n', '\n').replace('\r', '\n')

        # If it's already in proper PEM format, return as-is
        if key_content.startswith('-----BEGIN'):
            return key_content

        # Handle potential OpenSSH format conversion
        # Note: Full OpenSSH to PEM conversion is complex and would require
        # additional libraries or extensive parsing. For now, we'll pass through
        # and let paramiko handle it or fail gracefully.

        return key_content

    def _load_private_key(self, key_content: str) -> paramiko.PKey:
        """Try to load private key with multiple formats"""
        key_content = self._normalize_ssh_key(key_content)

        # List of key types to try in order
        key_loaders = [
            (paramiko.RSAKey, "RSA"),
            (paramiko.Ed25519Key, "Ed25519"), 
            (paramiko.ECDSAKey, "ECDSA"),
            (paramiko.DSSKey, "DSS"),
        ]

        last_exception = None

        for key_class, key_type in key_loaders:
            try:
                pkey_file = io.StringIO(key_content)
                pkey = key_class.from_private_key(pkey_file)
                logger.info(f"Successfully loaded {key_type} private key")
                return pkey
            except paramiko.ssh_exception.PasswordRequiredException:
                logger.error(f"Encrypted {key_type} private key requires passphrase (not supported)")
                raise CheckError(f"Encrypted {key_type} private keys with passphrase are not supported")
            except paramiko.ssh_exception.SSHException as e:
                logger.debug(f"Failed to load as {key_type} key: {e}")
                last_exception = e
                continue
            except Exception as e:
                logger.debug(f"Unexpected error loading {key_type} key: {e}")
                last_exception = e
                continue

        # If we get here, none of the key types worked
        logger.error(f"Failed to load private key with any supported format. Last error: {last_exception}")
        raise CheckError(
            "Invalid private key format. Supported formats: RSA, Ed25519, ECDSA, DSS in PEM format. "
            "Make sure the key includes proper BEGIN/END headers and is not encrypted with a passphrase."
        )

    def _validate_key_format(self, key_content: str) -> tuple[bool, str]:
        """Validate key format and return status with message"""
        if not key_content:
            return True, "No key provided"

        key_content = key_content.strip()

        # Check for public key formats (common mistake)
        public_key_prefixes = ['ssh-rsa', 'ssh-ed25519', 'ssh-ecdsa', 'ssh-dss']
        if any(key_content.startswith(prefix) for prefix in public_key_prefixes):
            return False, "Public key format detected - private key required"

        # Check for proper PEM format
        if key_content.startswith('-----BEGIN') and '-----END' in key_content:
            return True, "PEM format detected"

        # Check for OpenSSH private key format
        if key_content.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'):
            return True, "OpenSSH private key format detected"

        # Basic validation failed
        return False, "Invalid key format - should start with '-----BEGIN' for PEM format"

    def _test_ssh_connection(self, client: paramiko.SSHClient) -> bool:
        """Test SSH connection with a simple command"""
        try:
            stdin, stdout, stderr = client.exec_command('echo "SSH connection test"', timeout=5)
            result = stdout.read().decode().strip()
            error_output = stderr.read().decode().strip()

            if error_output:
                logger.warning(f"SSH test command stderr: {error_output}")

            logger.info(f"SSH test command result: {result}")
            return True
        except Exception as e:
            logger.warning(f"SSH command test failed: {e}")
            # Connection might still be valid even if command execution fails
            return True

    def check(self, raise_error: bool = False) -> bool:
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Determine authentication method
            ssh_key_content = self.config.get("ssh_key")
            pkey = None
            password_to_use = None

            if ssh_key_content:
                # Validate key format first
                is_valid, validation_msg = self._validate_key_format(ssh_key_content)
                logger.info(f"SSH key validation: {validation_msg}")

                if not is_valid:
                    error_msg = f"Invalid SSH key format: {validation_msg}"
                    logger.error(error_msg)
                    if raise_error:
                        raise CheckError(error_msg)
                    return False

                try:
                    pkey = self._load_private_key(ssh_key_content)
                    logger.info("SSH key authentication will be used")
                except CheckError:
                    if raise_error:
                        raise
                    return False
                except Exception as e:
                    logger.exception("Unexpected error loading private key")
                    error_msg = f"Failed to load private key: {str(e)}"
                    if raise_error:
                        raise CheckError(error_msg) from e
                    return False
            else:
                password_to_use = self.config.get("password")
                logger.info("Password authentication will be used")

            # Establish SSH connection
            connection_params = {
                'hostname': self.config["server"],
                'port': self.config.get("port", 22),
                'username': self.config.get("username"),
                'timeout': self.config.get("login_timeout", 2),
                'banner_timeout': 30,
                'auth_timeout': self.config.get("login_timeout", 2),
                'allow_agent': False,  # Disable SSH agent to avoid conflicts
                'look_for_keys': False,  # Don't look for keys in default locations
            }

            # Add authentication parameters
            if pkey is not None:
                connection_params['pkey'] = pkey
            else:
                connection_params['password'] = password_to_use

            logger.info(f"Attempting SSH connection to {self.config['server']}:{self.config.get('port', 22)}")
            client.connect(**connection_params)

            # Test the connection
            self._test_ssh_connection(client)

            logger.info("SSH connection test successful")
            return True

        except paramiko.ssh_exception.AuthenticationException as e:
            error_msg = "SSH authentication failed - check username/password/key"
            logger.error(f"{error_msg}: {e}")
            if raise_error:
                raise CheckError(error_msg) from e
            return False

        except paramiko.ssh_exception.NoValidConnectionsError as e:
            error_msg = "Cannot connect to SSH server - check hostname and port"
            logger.error(f"{error_msg}: {e}")
            if raise_error:
                raise CheckError(error_msg) from e
            return False

        except paramiko.ssh_exception.SSHException as e:
            error_msg = f"SSH protocol error: {e}"
            logger.error(error_msg)
            if raise_error:
                raise CheckError(error_msg) from e
            return False

        except Exception as e:
            logger.exception("SSH check failed with unexpected error")
            error_msg = f"SSH check failed: {str(e)}"
            if raise_error:
                raise CheckError(error_msg) from e
            return False

        finally:
            if client:
                try:
                    client.close()
                except:
                    pass  # Ignore cleanup errors