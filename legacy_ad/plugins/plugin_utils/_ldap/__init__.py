# Copyright: (c) 2023, Ansible Project
# Copyright 2026 sustainablelobster
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""LDAP Helpers.

This contains the code needed to perform LDAP operations for plugins in this
collection. It should only be used by plugins in this collection as the
interface is not final and could be subject to change.
"""

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may change even in a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import socket
import ssl
import typing as t

# Ansible does not distribute typing metadata for its controller interfaces.
from ansible.errors import AnsibleError  # type: ignore[import-untyped]

_ldap_import_error: t.Optional[Exception] = None
try:
    import sansldap

# Preserve optional-package initialization failures for the inventory error.
except Exception as e:  # pylint: disable=broad-exception-caught
    _ldap_import_error = e

from ._authentication import ClientCertificate, NegotiateCredential, SimpleCredential
from ._certificate import load_client_certificate, load_trust_certificate
from ._lookup import lookup_ldap_server
from .client import Credential, SyncLDAPClient


# Arguments and their resolved values mirror the public connection options.
# Keeping the connection lifecycle together makes every cleanup path visible.
# pylint: disable-next=too-many-locals
def create_ldap_connection(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    auth_protocol: t.Optional[str] = None,
    ca_cert: t.Optional[str] = None,
    cert_validation: t.Optional[str] = None,
    certificate: t.Optional[str] = None,
    certificate_key: t.Optional[str] = None,
    certificate_password: t.Optional[str] = None,
    connection_timeout: int = 5,
    encrypt: bool = True,
    password: t.Optional[str] = None,
    port: t.Optional[int] = None,
    server: t.Optional[str] = None,
    tls_mode: t.Optional[str] = None,
    username: t.Optional[str] = None,
    domain_realm: t.Optional[str] = None,
    **kwargs: t.Any,  # Catches any other module option not needed here
) -> SyncLDAPClient:
    """Creates the LDAP client.

    Creates the LDAP client using the options specified. The options here
    correspond to the options defined in the ldap_connection doc fragment.

    :param auth_protocol: Simple, certificate, negotiate, kerberos, or ntlm.
    :param ca_cert: Trusted CA file/directory or inline PEM certificate.
    :param cert_validation: Always, ignore, or ignore_hostname validation.
    :param certificate: Certificate file or inline PEM, optionally with a key.
    :param certificate_key: Separate certificate key file or inline PEM.
    :param certificate_password: Certificate/key decryption password.
    :param connection_timeout: Seconds allowed to establish the connection.
    :param encrypt: Require TLS or authentication-layer confidentiality.
    :param password: Authentication password.
    :param port: LDAP service port.
    :param server: Directory hostname, or use DNS discovery when omitted.
    :param tls_mode: LDAPS or StartTLS, when TLS is desired.
    :param username: Authentication identity, or use the current credential.
    :param domain_realm: Realm for DNS discovery; otherwise use Kerberos config.
    :param kwargs: Unrelated inventory options, which are ignored.
    :returns: An authenticated LDAP connection which the caller must close.
    :raises ImportError: Required controller dependencies are unavailable.
    :raises ValueError: Authentication and encryption settings conflict.
    :raises AnsibleError: The LDAP server cannot be reached.
    :raises Exception: The original authentication or TLS failure, after cleanup.
    """
    del kwargs
    if _ldap_import_error:
        raise ImportError(str(_ldap_import_error)) from _ldap_import_error

    if not server:
        server, lookup_port = lookup_ldap_server(default_realm=domain_realm)
        if not port:
            port = lookup_port

    if port is None:
        port = 636 if tls_mode == "ldaps" else 389

    if tls_mode is None and port == 636:
        tls_mode = "ldaps"

    ssl_context = _tls_context(tls_mode, ca_cert, cert_validation)
    credential = _credential(
        auth_protocol=auth_protocol,
        ssl_context=ssl_context,
        tls_mode=tls_mode,
        certificate=certificate,
        certificate_key=certificate_key,
        certificate_password=certificate_password,
        username=username,
        password=password,
        encrypt=encrypt,
    )

    protocol = sansldap.LDAPClient()
    tls_sock: t.Optional[ssl.SSLSocket] = None
    try:
        sock = socket.create_connection((server, port), timeout=connection_timeout)
    except OSError as e:
        raise AnsibleError(f"Failed to connect to {server}:{port}: {e}") from e
    sock.settimeout(None)  # Set socket into blocking mode

    try:
        if ssl_context and tls_mode == "ldaps":
            tls_sock = sock = ssl_context.wrap_socket(sock, server_hostname=server)

        if ssl_context and tls_mode == "start_tls":
            SyncLDAPClient.start_tls(protocol, sock)
            tls_sock = sock = ssl_context.wrap_socket(sock, server_hostname=server)

        client = SyncLDAPClient(server, protocol, sock)
    # Authentication or TLS may raise library-specific errors; always release sockets.
    except Exception:  # pylint: disable=broad-exception-caught
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # The socket has already been shutdown for some other reason
            pass
        sock.close()
        raise

    try:
        if credential:
            credential.authenticate(client, tls_sock=tls_sock)

        return client
    # Authentication errors must not leave the client's reader thread running.
    except Exception:  # pylint: disable=broad-exception-caught
        client.close()
        raise


def _tls_context(
    tls_mode: t.Optional[str],
    ca_cert: t.Optional[str],
    cert_validation: t.Optional[str],
) -> t.Optional[ssl.SSLContext]:
    if not tls_mode:
        return None
    context = ssl.create_default_context()
    if ca_cert:
        load_trust_certificate(context, ca_cert)
    if cert_validation == "ignore":
        context.check_hostname = False
        context.verify_mode = ssl.VerifyMode.CERT_NONE
    elif cert_validation == "ignore_hostname":
        context.check_hostname = False
    return context


# Each argument maps directly to a documented authentication option.
def _credential(  # pylint: disable=too-many-arguments
    *,
    auth_protocol: t.Optional[str],
    ssl_context: t.Optional[ssl.SSLContext],
    tls_mode: t.Optional[str],
    certificate: t.Optional[str],
    certificate_key: t.Optional[str],
    certificate_password: t.Optional[str],
    username: t.Optional[str],
    password: t.Optional[str],
    encrypt: bool,
) -> t.Optional[Credential]:
    if not auth_protocol:
        auth_protocol = "certificate" if certificate and ssl_context else "negotiate"
    if auth_protocol == "simple":
        if encrypt and not ssl_context:
            raise ValueError("Cannot use simple auth with encryption.")
        return SimpleCredential(username, password)
    if auth_protocol == "certificate":
        if not ssl_context:
            raise ValueError("TLS must be used for certificate authentication")
        if not certificate:
            raise ValueError(
                "A certificate must be specified for certificate authentication"
            )
        load_client_certificate(
            ssl_context,
            certificate,
            key=certificate_key,
            password=certificate_password,
        )
        # LDAPS certificate binds are implicit; StartTLS needs SASL EXTERNAL.
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81
        return ClientCertificate() if tls_mode == "start_tls" else None
    return NegotiateCredential(
        username, password, protocol=auth_protocol, encrypt=encrypt
    )
