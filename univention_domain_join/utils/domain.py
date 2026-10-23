#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Auto-detection of the UCS domain and its DC master via DNS.

A UCS domain publishes a ``_domaincontroller_master._tcp.<domain>`` SRV
record; it is used both to find the master and to verify that a candidate
domain really is a UCS domain.
"""

import ipaddress
import socket
import subprocess
from typing import Iterable, List, Set

import dns.resolver


def _srv_query(name: str) -> list:
    """Query SRV records; works with dnspython 1.x (RHEL 8) and 2.x alike."""
    # dnspython < 2.0 (e.g. RHEL 8's python3-dns) only knows query(),
    # newer versions renamed it to resolve().
    resolver = dns.resolver.Resolver()
    query = getattr(resolver, 'resolve', None) or resolver.query
    return list(query(name, 'SRV'))


def get_master_ip_through_dns(domain: str) -> str:
    """Return the IP of the UCS DC master via its SRV record, or '' on failure."""
    try:
        response = _srv_query('_domaincontroller_master._tcp.%s.' % (domain,))
        master_fqdn = response[0].target.canonicalize().split(1)[0].to_text()
    except Exception:
        return ""
    return socket.gethostbyname(master_fqdn)


def get_ucs_domainname() -> str:
    """Auto-detect the UCS domain of this client.

    Tries, in order: the domain part of the local FQDN, reverse DNS of the
    machine's own IP addresses, and reverse DNS of the configured
    nameservers. Returns '' if no UCS domain could be found.
    """
    domainname = get_ucs_domainname_via_local_configuration()
    if not domainname:
        domainname = get_ucs_domainname_via_reverse_dns()
    if not domainname:
        domainname = get_ucs_domainname_of_dns_server()
    return domainname


def get_ucs_domainname_via_local_configuration() -> str:
    """Return the domain part of the local FQDN, or '' if there is none."""
    try:
        domainname = socket.getfqdn().split('.', 1)[1]
    except Exception:
        return ""
    return domainname


def get_ucs_domainname_via_reverse_dns() -> str:
    """Derive the UCS domain from reverse DNS of this machine's IP addresses."""
    return ips2name(get_all_ip_addresses())


def get_ucs_domainname_of_dns_server() -> str:
    """Derive the UCS domain from reverse DNS of the configured nameservers."""
    return ips2name(get_nameservers())


def get_nameservers() -> Set[str]:
    """Return the nameserver IPs configured in /etc/resolv.conf."""
    nameservers = set()
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == 'nameserver' and is_only_ip(parts[1]):
                    nameservers.add(parts[1])
    except IOError:
        pass
    return nameservers


def is_only_ip(line: str) -> bool:
    """Return True if the string is a plain IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(line.strip())
        return True
    except ValueError:
        return False


def get_all_ip_addresses() -> List[str]:
    """Return all non-loopback, non-link-local IP addresses of this machine."""
    # Parse `ip -o addr show` instead of using netifaces, which is not
    # packaged for all RPM distributions.
    ip_addresses = []
    try:
        output = subprocess.check_output(['ip', '-o', 'addr', 'show']).decode()
    except (OSError, subprocess.CalledProcessError):
        return ip_addresses
    for line in output.splitlines():
        parts = line.split()
        try:
            family_index = next(i for i, p in enumerate(parts) if p in ('inet', 'inet6'))
        except StopIteration:
            continue
        if parts[1] == 'lo':
            continue
        if 'scope' in parts and parts[parts.index('scope') + 1] == 'link':
            continue  # skip link-local IPv6 addresses
        ip_addresses.append(parts[family_index + 1].split('/')[0])
    return ip_addresses


def ips2name(addrs: Iterable[str]) -> str:
    """Return the UCS domain found via reverse DNS of the first matching address."""
    for addr in addrs:
        fqdn = socket.getfqdn(addr)
        domainname = get_ucs_domainname_from_fqdn(fqdn)
        if domainname:
            return domainname
    return ""


def get_ucs_domainname_from_fqdn(fqdn: str) -> str:
    """Return the domain part of the FQDN if it is a UCS domain, else ''.

    A domain only counts as a UCS domain if the
    ``_domaincontroller_master._tcp`` SRV record exists for it.
    """
    try:
        domainname = fqdn.split('.', 1)[1]
        # Check if the _domaincontroller_master._tcp record exists, to ensure
        # that this is an UCS domain.
        _srv_query('_domaincontroller_master._tcp.%s' % (domainname,))
    except Exception:
        return ""
    return domainname
