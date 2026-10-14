# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Use Windows' LDAP client with encrypted SSPI authentication."""

import ctypes
import os
import re

SCOPE_BASE = 0
SCOPE_ONE_LEVEL = 1
SCOPE_SUBTREE = 2
SHOW_DELETED = "1.2.840.113556.1.4.417"
SD_FLAGS = "1.2.840.113556.1.4.801"
PAGED_RESULTS = "1.2.840.113556.1.4.319"
_NO_SUCH_OBJECT = 32
_NO_RESULTS = 94


class LDAPError(OSError):
    """An LDAP operation failed without returning a successful partial result."""


# These structures describe the WinLDAP ABI, not Python-owned application state.
class _Berval(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("length", ctypes.c_uint32), ("value", ctypes.c_void_p)]


class _Control(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("oid", ctypes.c_wchar_p),
        ("value", _Berval),
        ("critical", ctypes.c_ubyte),
    ]


class _Timeval(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("seconds", ctypes.c_int32), ("microseconds", ctypes.c_int32)]


class _Identity(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("user", ctypes.c_wchar_p),
        ("user_length", ctypes.c_uint32),
        ("domain", ctypes.c_wchar_p),
        ("domain_length", ctypes.c_uint32),
        ("password", ctypes.c_wchar_p),
        ("password_length", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
    ]


class _Modification(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("operation", ctypes.c_uint32),
        ("name", ctypes.c_wchar_p),
        ("values", ctypes.POINTER(ctypes.POINTER(_Berval))),
    ]


def _library():
    if os.name != "nt":
        raise ValueError("Active Directory modules require a Windows target.")
    # WinLDAP's LDAPAPI is __cdecl, including on 32-bit XP/Server 2003.
    # WinDLL's stdcall would corrupt the caller's stack on those targets.
    library = ctypes.CDLL("wldap32", use_last_error=True)
    pointer = ctypes.c_void_p
    text = ctypes.c_wchar_p
    number = ctypes.c_uint32
    controls = ctypes.POINTER(ctypes.POINTER(_Control))
    values = ctypes.POINTER(ctypes.POINTER(_Berval))
    modifications = ctypes.POINTER(ctypes.POINTER(_Modification))
    signatures = (
        ("ldap_initW", [text, number], pointer),
        ("ldap_set_optionW", [pointer, ctypes.c_int, pointer], number),
        ("ldap_connect", [pointer, ctypes.POINTER(_Timeval)], number),
        ("ldap_bind_sW", [pointer, text, pointer, number], number),
        ("ldap_unbind", [pointer], number),
        ("ldap_err2stringW", [number], text),
        ("LdapGetLastError", [], number),
        (
            "ldap_search_ext_sW",
            [
                pointer,
                text,
                number,
                text,
                ctypes.POINTER(text),
                number,
                controls,
                controls,
                ctypes.POINTER(_Timeval),
                number,
                ctypes.POINTER(pointer),
            ],
            number,
        ),
        (
            "ldap_search_init_pageW",
            [
                pointer,
                text,
                number,
                text,
                ctypes.POINTER(text),
                number,
                controls,
                controls,
                number,
                number,
                pointer,
            ],
            pointer,
        ),
        (
            "ldap_get_next_page_s",
            [
                pointer,
                pointer,
                ctypes.POINTER(_Timeval),
                number,
                ctypes.POINTER(number),
                ctypes.POINTER(pointer),
            ],
            number,
        ),
        ("ldap_search_abandon_page", [pointer, pointer], number),
        ("ldap_add_ext_sW", [pointer, text, modifications, controls, controls], number),
        (
            "ldap_modify_ext_sW",
            [pointer, text, modifications, controls, controls],
            number,
        ),
        ("ldap_delete_ext_sW", [pointer, text, controls, controls], number),
        (
            "ldap_rename_ext_sW",
            [pointer, text, text, text, ctypes.c_int, controls, controls],
            number,
        ),
        ("ldap_first_entry", [pointer, pointer], pointer),
        ("ldap_next_entry", [pointer, pointer], pointer),
        ("ldap_get_dnW", [pointer, pointer], pointer),
        ("ldap_first_attributeW", [pointer, pointer, ctypes.POINTER(pointer)], pointer),
        ("ldap_next_attributeW", [pointer, pointer, pointer], pointer),
        ("ldap_get_values_lenW", [pointer, pointer, text], values),
        ("ldap_value_free_len", [values], number),
        ("ldap_memfreeW", [pointer], None),
        ("ldap_msgfree", [pointer], number),
        ("ber_free", [pointer, ctypes.c_int], None),
    )
    for name, arguments, result in signatures:
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = result
    return library


def escape_filter(value):
    """Escape an assertion value, including binary values, for an LDAP filter.

    :param value: Text or bytes to include as an LDAP assertion value.
    :type value: str or bytes
    :returns: An RFC 4515 assertion value, not a complete filter.
    :rtype: str
    """
    if isinstance(value, bytes):
        return "".join("\\{0:02x}".format(byte) for byte in value)
    return "".join(
        "\\{0:02x}".format(ord(character)) if character in "\x00()*\\" else character
        for character in value
    )


def _text(value, name):
    if value is not None and (not isinstance(value, str) or "\0" in value):
        raise ValueError(name + " must be text without NUL characters.")
    return value


def _server(value):
    _text(value, "domain_server")
    if value is None:
        return None, 389
    if not value:
        raise ValueError("domain_server must not be empty.")
    # WinLDAP accepts DNS and NetBIOS names. A trailing port selects a GC or
    # other explicit LDAP endpoint without teaching the payload a transport.
    match = re.match(r"^(.+):([0-9]+)$", value)
    if match:
        port = int(match.group(2))
        if not 1 <= port <= 65535:
            raise ValueError("domain_server port must be between 1 and 65535.")
        return match.group(1), port
    return value, 389


def _credential(username, password):
    domain = ""
    user = username
    if "\\" in username:
        domain, user = username.split("\\", 1)
    # Python 3.4 Windows uses UTF-16 wchar_t; allocate code units explicitly so
    # a supplementary character cannot consume the terminator's buffer slot.
    buffers = [
        ctypes.create_unicode_buffer(text, len(text.encode("utf-16-le")) // 2 + 1)
        for text in (user, domain, password)
    ]
    fields = []
    for buffer, text in zip(buffers, (user, domain, password)):
        fields.extend(
            (ctypes.cast(buffer, ctypes.c_wchar_p), len(text.encode("utf-16-le")) // 2)
        )
    fields.append(2)
    # Python 3.4 cannot put a trailing comma after a keyword that follows an
    # unpacked positional argument. Keep the ABI's seven fields in one unpack.
    identity = _Identity(*fields)
    return identity, buffers


def _controls(include_deleted, security_descriptor):
    values = []
    buffers = []
    if include_deleted:
        values.append(_Control(SHOW_DELETED, _Berval(), 1))
    if security_descriptor:
        # Owner, group and DACL are readable without requesting the privileged
        # SACL. The control's value is the DER encoding of SEQUENCE INTEGER 7.
        buffer = ctypes.create_string_buffer(b"\x30\x03\x02\x01\x07")
        buffers.append(buffer)
        values.append(
            _Control(SD_FLAGS, _Berval(5, ctypes.cast(buffer, ctypes.c_void_p)), 1)
        )
    array = (ctypes.POINTER(_Control) * (len(values) + 1))()
    for index, value in enumerate(values):
        array[index] = ctypes.pointer(value)
    return array, values, buffers


def _modifications(changes):
    array = (ctypes.POINTER(_Modification) * (len(changes) + 1))()
    owners = []
    for index, (operation, name, values) in enumerate(changes):
        if operation not in (0, 1, 2):
            raise ValueError("Invalid LDAP modification operation.")
        _text(name, "attribute name")
        raw_values = (ctypes.POINTER(_Berval) * (len(values) + 1))()
        owners.append(raw_values)
        for position, value in enumerate(values):
            if not isinstance(value, bytes):
                raise ValueError("LDAP modifications require encoded byte values.")
            buffer = ctypes.create_string_buffer(value)
            encoded = _Berval(len(value), ctypes.cast(buffer, ctypes.c_void_p))
            raw_values[position] = ctypes.pointer(encoded)
            owners.extend((buffer, encoded))
        # A whole-attribute delete uses NULL, not an empty value array. WinLDAP
        # treats NULL replacement differently from a DELETE operation.
        modification = _Modification(
            operation | 0x80, name, raw_values if values else None
        )
        array[index] = ctypes.pointer(modification)
        owners.append(modification)
    return array, owners


class LDAPConnection:
    """Own a signed and sealed WinLDAP connection and copied search results.

    :param server: Optional DNS/NetBIOS server name, optionally with a port.
    :param username: Optional explicit domain account or UPN.
    :param password: Password paired with an explicit username.
    :raises LDAPError: If connection, negotiation, or an LDAP operation fails.
    :raises ValueError: If arguments are invalid or the target is not Windows.
    """

    def __init__(self, server=None, username=None, password=None):
        host, port = _server(server)
        for value, name in (
            (username, "domain_username"),
            (password, "domain_password"),
        ):
            _text(value, name)
        if (username is None) != (password is None):
            raise ValueError(
                "domain_username and domain_password must be supplied together."
            )
        self.library = _library()
        self.handle = self.library.ldap_initW(host, port)
        self._root = None
        if not self.handle:
            self._check(self.library.LdapGetLastError(), "Initialize LDAP")
            raise LDAPError("Initialize LDAP returned no connection.")
        try:
            version = ctypes.c_uint32(3)
            self._check(
                self.library.ldap_set_optionW(self.handle, 0x11, ctypes.byref(version)),
                "Select LDAPv3",
            )
            # LDAP_OPT_ON is the literal pointer value 1 for Boolean options.
            # Negotiate supplies credentials through SSPI, never a simple bind.
            for option in (0x95, 0x96):
                self._check(
                    self.library.ldap_set_optionW(
                        self.handle, option, ctypes.c_void_p(1)
                    ),
                    "Require LDAP signing and encryption",
                )
            self._check(
                self.library.ldap_connect(self.handle, ctypes.byref(_Timeval(60, 0))),
                "Connect to Active Directory",
            )
            credential = None
            buffers = []
            if username is not None:
                credential, buffers = _credential(username, password)
            try:
                self._check(
                    self.library.ldap_bind_sW(
                        self.handle,
                        None,
                        ctypes.byref(credential) if credential else None,
                        0x486,
                    ),
                    "Authenticate to Active Directory",
                )
            finally:
                for buffer in buffers:
                    ctypes.memset(ctypes.addressof(buffer), 0, ctypes.sizeof(buffer))
        except Exception:
            self.close()
            raise

    def _check(self, status, operation):
        if status:
            text = self.library.ldap_err2stringW(status) or "Unknown LDAP error"
            hint = ""
            if status in (49, 81, 82):
                hint = (
                    " Supply domain credentials or use a delegated/become logon"
                    " with domain access."
                )
            raise LDAPError(
                status, "{0}: {1} (LDAP {2}).{3}".format(operation, text, status, hint)
            )

    def close(self):
        """Release the native connection; repeated calls have no effect."""
        if self.handle:
            self.library.ldap_unbind(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.close()

    @property
    def root_dse(self):
        """Read the directory's naming contexts and supported controls once.

        :returns: RootDSE attributes indexed by lowercase LDAP name.
        :rtype: dict
        :raises ValueError: If the server returns no unique rootDSE.
        """
        if self._root is None:
            results = self.search(
                "",
                SCOPE_BASE,
                "(objectClass=*)",
                [
                    "defaultNamingContext",
                    "schemaNamingContext",
                    "configurationNamingContext",
                    "rootDomainNamingContext",
                    "supportedControl",
                    "dnsHostName",
                ],
            )
            if len(results) != 1:
                raise ValueError(
                    "The LDAP server did not return an Active Directory rootDSE."
                )
            self._root = {
                name.lower(): values
                for name, values in results[0]["attributes"].items()
            }
        return self._root

    def naming_context(self, name="defaultNamingContext"):
        """Return one advertised naming context or fail rather than guessing.

        :param name: The rootDSE naming-context property to read.
        :type name: str
        :returns: The directory distinguished name.
        :rtype: str
        :raises ValueError: If the server does not advertise that context.
        """
        values = self.root_dse.get(name.lower(), [])
        if not values:
            raise ValueError("The LDAP server has no " + name + ".")
        return values[0].decode("utf-8")

    def add(self, dn, attributes):
        """Create one directory entry with encoded attribute values.

        :param dn: Distinguished name of the new entry.
        :type dn: str
        :param attributes: LDAP attribute names mapped to byte-value lists.
        :type attributes: dict[str, list[bytes]]
        :raises LDAPError: If the directory rejects the creation.
        """
        _text(dn, "distinguished name")
        modifications, _owners = _modifications(
            [(0, name, values) for name, values in attributes.items() if values]
        )
        self._check(
            self.library.ldap_add_ext_sW(self.handle, dn, modifications, None, None),
            "Create AD object " + dn,
        )

    def modify(self, dn, changes):
        """Apply one ordered LDAP modification request.

        :param dn: Distinguished name of the existing entry.
        :type dn: str
        :param changes: Tuples of add/delete/replace operation, name and bytes.
        :type changes: list[tuple]
        :raises LDAPError: If the directory rejects a modification.
        """
        _text(dn, "distinguished name")
        modifications, _owners = _modifications(changes)
        descriptor = any(
            name.lower() == "ntsecuritydescriptor"
            for _operation, name, _data in changes
        )
        controls, _values, _buffers = _controls(False, descriptor)
        self._check(
            self.library.ldap_modify_ext_sW(
                self.handle, dn, modifications, controls, None
            ),
            "Update AD object " + dn,
        )

    def rename(self, dn, rdn, parent):
        """Rename or move one entry without retaining its old RDN value.

        :param dn: Current distinguished name.
        :type dn: str
        :param rdn: Desired relative distinguished name.
        :type rdn: str
        :param parent: Distinguished name of the desired parent container.
        :type parent: str
        :raises LDAPError: If the directory rejects the rename or move.
        """
        for value in (dn, rdn, parent):
            _text(value, "distinguished name")
        self._check(
            self.library.ldap_rename_ext_sW(
                self.handle, dn, rdn, parent, 1, None, None
            ),
            "Move or rename AD object " + dn,
        )

    def delete(self, dn):
        """Remove one childless entry; callers own recursive deletion ordering.

        :param dn: Distinguished name of the entry to remove.
        :type dn: str
        :raises LDAPError: If the directory rejects deletion.
        """
        _text(dn, "distinguished name")
        self._check(
            self.library.ldap_delete_ext_sW(self.handle, dn, None, None),
            "Delete AD object " + dn,
        )

    def _entries(self, result):
        entries = []
        entry = self.library.ldap_first_entry(self.handle, result)
        while entry:
            pointer = self.library.ldap_get_dnW(self.handle, entry)
            try:
                if not pointer:
                    self._check(
                        self.library.LdapGetLastError(),
                        "Read object distinguished name",
                    )
                    raise ValueError(
                        "LDAP returned an object without a distinguished name."
                    )
                dn = ctypes.wstring_at(pointer)
            finally:
                if pointer:
                    self.library.ldap_memfreeW(pointer)
            entries.append({"dn": dn, "attributes": self._entry_attributes(entry)})
            entry = self.library.ldap_next_entry(self.handle, entry)
        return entries

    def _attribute_values(self, entry, name):
        values = self.library.ldap_get_values_lenW(self.handle, entry, name)
        try:
            if not values:
                self._check(self.library.LdapGetLastError(), "Read attribute " + name)
            copied = []
            index = 0
            while values and values[index]:
                value = values[index].contents
                copied.append(ctypes.string_at(value.value, value.length))
                index += 1
            return copied
        finally:
            if values:
                self.library.ldap_value_free_len(values)

    def _entry_attributes(self, entry):
        attributes = {}
        iterator = ctypes.c_void_p()
        name_pointer = self.library.ldap_first_attributeW(
            self.handle, entry, ctypes.byref(iterator)
        )
        try:
            while name_pointer:
                try:
                    name = ctypes.wstring_at(name_pointer)
                    attributes[name] = self._attribute_values(entry, name)
                finally:
                    self.library.ldap_memfreeW(name_pointer)
                name_pointer = self.library.ldap_next_attributeW(
                    self.handle, entry, iterator
                )
            return attributes
        finally:
            if iterator:
                self.library.ber_free(iterator, 0)

    def _search_base(self, base, ldap_filter, names, controls):
        result = ctypes.c_void_p()
        timeout = _Timeval(60, 0)
        try:
            status = self.library.ldap_search_ext_sW(
                self.handle,
                base,
                SCOPE_BASE,
                ldap_filter,
                names,
                0,
                controls,
                None,
                ctypes.byref(timeout),
                0,
                ctypes.byref(result),
            )
            self._check(status, "Search Active Directory")
            return self._entries(result)
        finally:
            if result:
                self.library.ldap_msgfree(result)

    # Keep the five LDAP request fields explicit at this native call boundary.
    def _search_paged(
        self, base, scope, ldap_filter, names, controls
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        page = self.library.ldap_search_init_pageW(
            self.handle,
            base,
            scope,
            ldap_filter,
            names,
            0,
            controls,
            None,
            60,
            0,
            None,
        )
        if not page:
            self._check(self.library.LdapGetLastError(), "Initialize paged search")
            raise ValueError("LDAP returned no paged-search handle.")
        timeout = _Timeval(60, 0)
        entries = []
        try:
            while True:
                result = ctypes.c_void_p()
                count = ctypes.c_uint32()
                try:
                    status = self.library.ldap_get_next_page_s(
                        self.handle,
                        page,
                        ctypes.byref(timeout),
                        256,
                        ctypes.byref(count),
                        ctypes.byref(result),
                    )
                    if status not in (0, _NO_RESULTS):
                        self._check(status, "Search Active Directory")
                    if result:
                        entries.extend(self._entries(result))
                finally:
                    if result:
                        self.library.ldap_msgfree(result)
                if status == _NO_RESULTS:
                    return entries
        finally:
            self.library.ldap_search_abandon_page(self.handle, page)

    # The four LDAP query fields and two independent server controls are the
    # public contract; keep native array owners alive in this scope until reads finish.
    # pylint: disable=too-many-arguments,too-many-locals
    # Python 3.4 rejects a trailing comma after keyword-only parameters.
    # Black retains one here even with py34; exclude only this signature.
    # fmt: off
    def search(
        self,
        base,
        scope,
        ldap_filter,
        attributes,
        *,
        include_deleted=False,
        security_descriptor=False,
        _ranges=True
    ):
    # fmt: on
        """Read all matching entries, paging and completing ranged attributes.

        :param base: Search-base distinguished name; empty means rootDSE/GC.
        :type base: str
        :param scope: SCOPE_BASE, SCOPE_ONE_LEVEL, or SCOPE_SUBTREE.
        :type scope: int
        :param ldap_filter: An LDAP filter, passed to WinLDAP without evaluation.
        :type ldap_filter: str
        :param attributes: Attribute names to retrieve, including optional '*'.
        :type attributes: list[str]
        :param include_deleted: Request the critical show-deleted control.
        :type include_deleted: bool
        :param security_descriptor: Request owner, group and DACL components.
        :type security_descriptor: bool
        :returns: Entries containing 'dn' and an attribute-to-bytes-list mapping.
        :rtype: list[dict]
        :raises ValueError: If inputs or requested server capabilities are invalid.
        :raises LDAPError: If any page fails; partial results are not returned.
        """
        _text(base, "search_base")
        _text(ldap_filter, "ldap_filter")
        if scope not in (SCOPE_BASE, SCOPE_ONE_LEVEL, SCOPE_SUBTREE):
            raise ValueError("Invalid LDAP search scope.")
        if include_deleted:
            supported = self.root_dse.get("supportedcontrol", [])
            if SHOW_DELETED.encode("ascii") not in supported:
                raise ValueError(
                    "The directory does not support searches of deleted objects."
                )
        names = (ctypes.c_wchar_p * (len(attributes) + 1))()
        for index, name in enumerate(attributes):
            names[index] = _text(name, "properties")
        controls, _values, _buffers = _controls(include_deleted, security_descriptor)
        if scope == SCOPE_BASE:
            entries = self._search_base(base, ldap_filter, names, controls)
        else:
            entries = self._search_paged(base, scope, ldap_filter, names, controls)
        if _ranges:
            for entry in entries:
                self._complete_ranges(entry, include_deleted, security_descriptor)
        return entries

    # pylint: enable=too-many-arguments,too-many-locals

    # Keep the server's range boundaries and copied chunks visible together.
    def _complete_ranges(
        self, entry, include_deleted, security_descriptor
    ):  # pylint: disable=too-many-locals
        attributes = entry["attributes"]
        for name in list(attributes):
            match = re.match(r"^(.+);range=0-([0-9]+|\*)$", name, re.I)
            if not match:
                continue
            plain = match.group(1)
            values = attributes.pop(name)
            end = match.group(2)
            while end != "*":
                start = int(end) + 1
                requested = "{0};range={1}-*".format(plain, start)
                rows = self.search(
                    entry["dn"],
                    SCOPE_BASE,
                    "(objectClass=*)",
                    [requested],
                    include_deleted=include_deleted,
                    security_descriptor=security_descriptor,
                    _ranges=False,
                )
                if len(rows) != 1:
                    raise ValueError(
                        "Object disappeared during ranged attribute retrieval: "
                        + entry["dn"]
                    )
                matches = [
                    (key, data)
                    for key, data in rows[0]["attributes"].items()
                    if re.match(
                        r"^{0};range={1}-([0-9]+|\*)$".format(re.escape(plain), start),
                        key,
                        re.I,
                    )
                ]
                if len(matches) != 1:
                    raise ValueError(
                        "The directory did not complete ranged attribute " + plain + "."
                    )
                ranged, chunk = matches[0]
                end = ranged.rsplit("-", 1)[1]
                if end != "*" and (int(end) < start or not chunk):
                    raise ValueError(
                        "The directory returned a non-progressing attribute range for "
                        + plain
                        + "."
                    )
                values.extend(chunk)
            attributes[plain] = values
