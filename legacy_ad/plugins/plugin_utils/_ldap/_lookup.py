"""Discover controller LDAP endpoints using DNS and Kerberos configuration."""

# Copyright: (c) 2023, Ansible Project
# Copyright 2026 sustainablelobster
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may change even in a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import typing as t

# dnspython is used for dynamic server lookups
try:
    import dns.resolver

    HAS_DNSPYTHON = True
# Optional binary or resolver packages may fail during initialization.
except Exception:  # pylint: disable=broad-exception-caught
    HAS_DNSPYTHON = False


# krb5 is used to retrieve the default realm for dynamic server lookups.
try:
    import krb5

    HAS_KRB5 = True
# Optional binary or resolver packages may fail during initialization.
except Exception:  # pylint: disable=broad-exception-caught
    HAS_KRB5 = False


class SrvRecord(t.NamedTuple):
    """LDAP service endpoint and its DNS priority/weight ordering."""

    target: str
    port: int
    weight: int
    priority: int

    @classmethod
    def lookup(
        cls,
        service: str,
        proto: str,
        name: str,
    ) -> t.List["SrvRecord"]:
        """Performs an SRV lookup.

        :param service: SRV service name, without its leading underscore.
        :param proto: SRV transport protocol, without its leading underscore.
        :param name: DNS domain containing the service.
        :returns: Records ordered by lowest priority and highest weight.
        """
        record = f"_{service}._{proto}.{name}"

        answers: t.List[SrvRecord] = []
        for answer in dns.resolver.resolve(record, "SRV"):
            answers.append(
                SrvRecord(
                    target=str(answer.target),
                    port=answer.port,
                    weight=answer.weight,
                    priority=answer.priority,
                )
            )

        # Sorts the array by lowest priority then highest weight.
        return sorted(answers, key=lambda a: (a.priority, -a.weight))


def lookup_ldap_server(
    default_realm: t.Optional[str] = None,
) -> t.Tuple[str, int]:
    """Attempts to lookup LDAP server.

    Attempts to lookup LDAP server based on the current Kerberos host
    configuration and '_ldap._tcp.dc._msdcs.{realm}' SRV records.

    :param default_realm: Domain realm; otherwise use Kerberos's default realm.
    :returns: The selected LDAP hostname and port.
    :raises ImportError: A required DNS or Kerberos package is unavailable.
    """
    required_libs = [(HAS_DNSPYTHON, "dnspython")]
    if not default_realm:
        required_libs.append((HAS_KRB5, "krb5"))

    missing_libs = [lib for present, lib in required_libs if not present]
    if missing_libs:
        raise ImportError(
            "Cannot lookup server without the python libraries "
            + ", ".join(missing_libs)
        )

    if not default_realm:
        ctx = krb5.init_context()
        default_realm = krb5.get_default_realm(ctx).decode("utf-8")

    answer = SrvRecord.lookup("ldap", "tcp", f"dc._msdcs.{default_realm}")[0]
    return answer.target, answer.port
