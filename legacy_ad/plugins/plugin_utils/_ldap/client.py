"""Run the maintained sansldap protocol over a synchronous controller socket."""

# Copyright: (c) 2023, Ansible Project
# Copyright 2026 sustainablelobster
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may change even in a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import dataclasses
import socket
import ssl
import threading
import typing as t

try:
    import sansldap
# The inventory entry point reports complete optional-dependency import failures.
except Exception:  # pylint: disable=broad-exception-caught
    pass  # Check is in __init__.py


MessageT = t.TypeVar("MessageT", bound="sansldap.LDAPMessage")


# Credentials implement exactly one authentication operation for the LDAP client.
class Credential:  # pylint: disable=too-few-public-methods
    """Credential for LDAP client.

    Base object used to implementation authentication for the LDAP client.
    """

    def authenticate(
        self,
        client: "SyncLDAPClient",
        *,
        tls_sock: t.Optional[ssl.SSLSocket] = None,
    ) -> None:
        """Authenticate a connection using this credential implementation.

        :param client: Controller LDAP connection to bind.
        :param tls_sock: TLS socket, when channel binding is required.
        :raises NotImplementedError: Subclasses must implement authentication.
        """
        raise NotImplementedError()


class MessageEncryptor:
    """Message encryptor for LDAP client.

    Base object used by the LDAP client to encrypt and decrypt messages.
    """

    def wrap(
        self,
        data: bytes,
    ) -> bytes:
        """Protect an outgoing LDAP message.

        :param data: Encoded LDAP message bytes.
        :returns: Protected bytes with the required transport framing.
        :raises NotImplementedError: Subclasses must implement encryption.
        """
        raise NotImplementedError()

    def unwrap(
        self,
        data: bytes,
    ) -> t.Tuple[bytes, int]:
        """Unprotect one framed LDAP message.

        :param data: Received protected bytes, possibly an incomplete frame.
        :returns: Plaintext and consumed length, or empty bytes and zero.
        :raises NotImplementedError: Subclasses must implement decryption.
        """
        raise NotImplementedError()


class LDAPResultError(Exception):
    """LDAP operation failure preserving result code and server diagnostics."""

    def __init__(
        self,
        msg: str,
        result: "sansldap.LDAPResult",
    ) -> None:
        super().__init__(msg)
        self.result = result

    def __str__(self) -> str:
        inner_msg = super().__str__()
        msg = f"Received LDAPResult error {inner_msg} - {self.result.result_code.name}"
        if self.result.matched_dn:
            msg += f" - Matched DN {self.result.matched_dn}"

        if self.result.diagnostics_message:
            msg += f" - {self.result.diagnostics_message}"

        return msg


class ResponseHandler(t.Generic[MessageT]):
    """Route received replies to the waiting LDAP operation by message identifier."""

    def __init__(
        self,
        message_id: int,
        message_types: t.Tuple[t.Type[MessageT], ...],
    ) -> None:
        self._message_id = message_id
        self._message_types = message_types
        self._condition = threading.Condition()
        self._exp: t.Optional[Exception] = None
        self._results: t.List[MessageT] = []

    def __iter__(self) -> t.Iterator[MessageT]:
        return self._iter_next()

    def append(
        self,
        value: t.Union[Exception, MessageT],
    ) -> None:
        """Notify the waiting operation of a matching reply or reader failure.

        :param value: Decoded LDAP response, or an exception from the reader.
        """
        with self._condition:
            if isinstance(value, Exception):
                self._exp = value
            elif (
                isinstance(value, self._message_types)
                and value.message_id == self._message_id
            ):
                self._results.append(value)
            else:
                return

            self._condition.notify_all()

    def _iter_next(self) -> t.Iterator[MessageT]:
        idx = 0
        while True:
            with self._condition:
                if self._exp:
                    raise RuntimeError(
                        f"Exception from receiving task: {self._exp}"
                    ) from self._exp

                if idx < len(self._results):
                    value = self._results[idx]
                    idx += 1
                    yield value

                else:
                    self._condition.wait()


@dataclasses.dataclass(frozen=True)
class RootDSE:
    """Naming context, subschema reference, and directory search capabilities."""

    default_naming_context: str
    subschema_subentry: str
    supported_controls: t.List[str]


# Socket, protocol, reader, protection, replies, and cached metadata belong to
# one connection; splitting that state would obscure its cleanup lifecycle.
class SyncLDAPClient:  # pylint: disable=too-many-instance-attributes
    """Synchronous LDAP operations with maintained protocol and message protection."""

    def __init__(
        self,
        server: str,
        protocol: "sansldap.LDAPClient",
        sock: t.Union[socket.socket, ssl.SSLSocket],
    ) -> None:
        self.server = server

        self._protocol = protocol
        self._sock = sock
        self._response_handler: t.List[ResponseHandler[t.Any]] = []
        self._encryptor: t.Optional[MessageEncryptor] = None
        self._reader_error: t.Optional[Exception] = None
        self._reader_task = threading.Thread(
            target=self._read_loop,
            name=f"LDAP({server})",
        )
        self._reader_task.start()
        self._root_dse: t.Optional[RootDSE] = None

    @property
    def root_dse(self) -> RootDSE:
        """Read and cache the directory's root metadata.

        :returns: Default search base, schema path, and supported controls.
        """
        if not self._root_dse:
            default_naming_context = ""
            subschema_subentry = ""
            supported_controls: t.List[str] = []

            for res in self._search_request(
                base_object="",
                scope=sansldap.SearchScope.BASE,
                filter=sansldap.FilterPresent("objectClass"),
                attributes=[
                    "defaultNamingContext",
                    "subschemaSubentry",
                    "supportedControl",
                ],
            ):
                if not isinstance(res, sansldap.SearchResultEntry):
                    continue

                for attr in res.attributes:
                    if attr.name == "defaultNamingContext":
                        default_naming_context = attr.values[0].decode("utf-8")

                    elif attr.name == "subschemaSubentry":
                        subschema_subentry = attr.values[0].decode("utf-8")

                    elif attr.name == "supportedControl":
                        supported_controls = [v.decode("utf-8") for v in attr.values]

            self._root_dse = RootDSE(
                default_naming_context=default_naming_context,
                subschema_subentry=subschema_subentry,
                supported_controls=supported_controls,
            )

        return self._root_dse

    def __enter__(self) -> "SyncLDAPClient":
        return self

    def __exit__(self, *args: t.Any, **kwargs: t.Any) -> None:
        self.close()

    @classmethod
    def start_tls(
        cls,
        protocol: "sansldap.LDAPClient",
        sock: socket.socket,
    ) -> None:
        """Request StartTLS before wrapping an established socket.

        :param protocol: sansldap protocol used by the connection.
        :param sock: Unencrypted socket to the LDAP service.
        :raises LDAPResultError: The directory rejects StartTLS.
        :raises ConnectionError: The directory closes before answering.
        """
        protocol.extended_request(sansldap.ExtendedOperations.LDAP_START_TLS)
        data = protocol.data_to_send()
        sock.sendall(data)

        done = False
        while not done:
            data = sock.recv(4096)
            if not data:
                raise ConnectionError("LDAP connection closed during StartTLS")
            for msg in protocol.receive(data):
                msg = t.cast(sansldap.ExtendedResponse, msg)
                if msg.result.result_code != sansldap.LDAPResultCode.SUCCESS:
                    raise LDAPResultError("StartTLS failed", msg.result)

                done = True
                break

    def bind(
        self,
        dn: str,
        credential: "sansldap.AuthenticationCredential",
        success_only: bool = True,
    ) -> t.Optional[bytes]:
        """Authenticate with an LDAP bind and return any server SASL token.

        :param dn: Distinguished name, or empty for SASL negotiation.
        :param credential: sansldap simple or SASL bind credential.
        :param success_only: Reject intermediate SASL negotiation responses.
        :returns: The server SASL token, if one accompanies the response.
        :raises LDAPResultError: The bind result is not accepted.
        """
        msg_id = self._protocol.bind(dn, credential)
        response = self._write_and_wait_one(msg_id, sansldap.BindResponse)

        valid_codes = [sansldap.LDAPResultCode.SUCCESS]
        if not success_only:
            valid_codes.append(sansldap.LDAPResultCode.SASL_BIND_IN_PROGRESS)

        if response.result.result_code not in valid_codes:
            raise LDAPResultError("bind failed", response.result)

        return response.server_sasl_creds

    def close(self) -> None:
        """Close the socket and join its reader thread."""
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # The socket has already been shutdown for some other reason
            pass
        self._sock.close()
        self._reader_task.join()

    def register_encryptor(
        self,
        encryptor: MessageEncryptor,
    ) -> None:
        """Enable authentication-layer message protection after binding.

        :param encryptor: Message framing, encryption, and decryption adapter.
        """
        self._encryptor = encryptor

    def search(
        self,
        # The filter keyword is part of the upstream client interface.
        # pylint: disable-next=redefined-builtin
        filter: t.Union[str, "sansldap.LDAPFilter"],
        attributes: t.List[str],
        search_base: t.Optional[str] = None,
        search_scope: t.Optional["sansldap.SearchScope"] = None,
    ) -> t.Dict[str, t.Dict[str, t.List[bytes]]]:
        """Retrieve directory entries, following supported paged-search controls.

        :param filter: LDAP filter text or a parsed sansldap filter.
        :param attributes: Attribute names requested from each entry.
        :param search_base: Search DN; otherwise use the default naming context.
        :param search_scope: Base, one-level, or subtree search scope.
        :returns: Entries indexed by DN with attribute names and raw byte values.
        """
        if search_base is None:
            search_base = self.root_dse.default_naming_context

        controls: t.List[sansldap.LDAPControl] = []
        pagination_size = 1024

        if sansldap.PagedResultControl.control_type in self.root_dse.supported_controls:
            controls.append(
                # Pylint sees the base control's value argument; this subclass derives it.
                sansldap.PagedResultControl(  # pylint: disable=no-value-for-parameter
                    critical=False, size=pagination_size, cookie=b""
                )
            )

        search_kwargs: t.Dict[str, t.Any] = {
            "base_object": search_base,
            "scope": search_scope,
            "filter": filter,
            "attributes": attributes,
        }
        res: t.Dict[str, t.Dict[str, t.List[bytes]]] = {}

        while True:
            for entry in self._search_request(
                controls=controls,
                **search_kwargs,
            ):
                if isinstance(entry, sansldap.SearchResultDone):
                    paginated_control = next(
                        iter(
                            c
                            for c in entry.controls
                            if isinstance(c, sansldap.PagedResultControl)
                        ),
                        None,
                    )
                    if paginated_control and paginated_control.cookie:
                        controls = [
                            # Pylint sees a base field removed by the subclass dataclass.
                            sansldap.PagedResultControl(  # pylint: disable=no-value-for-parameter
                                critical=False,
                                size=pagination_size,
                                cookie=paginated_control.cookie,
                            )
                        ]
                    else:
                        controls = []

                elif isinstance(entry, sansldap.SearchResultEntry):
                    entry_res = res.setdefault(entry.object_name, {})
                    for attr in entry.attributes:
                        entry_attr = entry_res.setdefault(attr.name, [])
                        entry_attr.extend(attr.values)

                # SearchResultReference is ignored for now.

            if not controls:
                break

        return res

    # These arguments correspond directly to the standard LDAP SearchRequest.
    def _search_request(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        base_object: t.Optional[str] = None,
        scope: t.Optional[t.Union[int, "sansldap.SearchScope"]] = None,
        dereferencing_policy: t.Optional[
            t.Union[int, "sansldap.DereferencingPolicy"]
        ] = None,
        size_limit: int = 0,
        time_limit: int = 0,
        types_only: bool = False,
        # Preserve the LDAP protocol's filter keyword.
        # pylint: disable-next=redefined-builtin
        filter: t.Optional[t.Union[str, "sansldap.LDAPFilter"]] = None,
        attributes: t.Optional[t.List[str]] = None,
        controls: t.Optional[t.List["sansldap.LDAPControl"]] = None,
    ) -> t.Iterator[
        t.Union[
            "sansldap.SearchResultReference",
            "sansldap.SearchResultEntry",
            "sansldap.SearchResultDone",
        ]
    ]:
        ldap_filter: t.Optional[sansldap.LDAPFilter] = None
        if isinstance(filter, sansldap.LDAPFilter):
            ldap_filter = filter
        elif filter:
            ldap_filter = sansldap.LDAPFilter.from_string(filter)

        deref = (
            dereferencing_policy
            if dereferencing_policy is not None
            else sansldap.DereferencingPolicy.NEVER
        )

        msg_id = self._protocol.search_request(
            base_object=base_object,
            scope=scope if scope is not None else sansldap.SearchScope.SUBTREE,
            dereferencing_policy=deref,
            size_limit=size_limit,
            time_limit=time_limit,
            types_only=types_only,
            filter=ldap_filter,
            attributes=attributes,
            controls=controls,
        )

        handler = self._register_response_handler(
            msg_id,
            sansldap.SearchResultEntry,
            sansldap.SearchResultReference,
            sansldap.SearchResultDone,
        )
        try:
            self._write_msg()
            for res in handler:
                yield res  # type: ignore[misc]

                if isinstance(res, sansldap.SearchResultDone):
                    self._valid_result(res.result, "search request failed")
                    break

        finally:
            self._unregister_response_handler(handler)

    # Decode fragments, apply optional protection, and notify operation waiters together.
    def _read_loop(self) -> None:  # pylint: disable=too-many-branches
        data_buffer = bytearray()
        while True:
            try:
                resp = self._sock.recv(4096)
                if not resp:
                    raise ConnectionError("LDAP connection has been shutdown")

                data_buffer.extend(resp)

                while data_buffer:
                    if self._encryptor:
                        dec_data, enc_len = self._encryptor.unwrap(bytes(data_buffer))
                        if enc_len == 0:
                            break

                        data_buffer = data_buffer[enc_len:]
                    else:
                        dec_data = bytes(data_buffer)
                        data_buffer = bytearray()

                    for msg in self._protocol.receive(dec_data):
                        for handler in self._response_handler:
                            handler.append(msg)

            except sansldap.ProtocolError as e:
                self._reader_error = e
                if e.response:
                    self._sock.sendall(e.response)

                for handler in self._response_handler:
                    handler.append(e)
                break

            # Any decoding/socket error must wake waiting operations, not strand them.
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._reader_error = e
                for handler in self._response_handler:
                    handler.append(e)
                break

    def _register_response_handler(
        self,
        msg_id: int,
        *message_types: t.Type[MessageT],
    ) -> ResponseHandler[MessageT]:
        handler = ResponseHandler(
            msg_id,
            message_types,
        )
        self._response_handler.append(handler)
        if self._reader_error:
            handler.append(self._reader_error)

        return handler

    def _valid_result(
        self,
        result: "sansldap.LDAPResult",
        msg: str,
    ) -> None:
        if result.result_code != sansldap.LDAPResultCode.SUCCESS:
            raise LDAPResultError(msg, result)

    def _unregister_response_handler(
        self,
        handler: ResponseHandler[t.Any],
    ) -> None:
        self._response_handler.remove(handler)

    def _write_and_wait_one(
        self,
        msg_id: int,
        message_type: t.Type[MessageT],
    ) -> MessageT:
        handler = self._register_response_handler(msg_id, message_type)
        try:
            self._write_msg()

            return next(iter(handler))

        finally:
            self._unregister_response_handler(handler)

    def _write_msg(self) -> None:
        data = self._protocol.data_to_send()
        if self._encryptor:
            data = self._encryptor.wrap(data)

        self._sock.sendall(data)
