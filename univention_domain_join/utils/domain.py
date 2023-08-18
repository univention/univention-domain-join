#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

import socket
import subprocess
from typing import Iterable, List, Set

import dns.resolver
import IPy
import netifaces


def get_master_ip_through_dns(domain: str) -> str:
	resolver = dns.resolver.Resolver()
	try:
		response = resolver.query('_domaincontroller_master._tcp.%s.' % (domain,), 'SRV')
		master_fqdn = response[0].target.canonicalize().split(1)[0].to_text()
	except Exception:
		return ""
	return socket.gethostbyname(master_fqdn)


def get_ucs_domainname() -> str:
	domainname = get_ucs_domainname_via_local_configuration()
	if not domainname:
		domainname = get_ucs_domainname_via_reverse_dns()
	if not domainname:
		domainname = get_ucs_domainname_of_dns_server()
	return domainname


def get_ucs_domainname_via_local_configuration() -> str:
	try:
		domainname = socket.getfqdn().split('.', 1)[1]
	except Exception:
		return ""
	return domainname


def get_ucs_domainname_via_reverse_dns() -> str:
	return ips2name(get_all_ip_addresses())


def get_ucs_domainname_of_dns_server() -> str:
	return ips2name(get_nameservers())


def get_nameservers() -> Set[str]:
	output = subprocess.check_output(['resolvectl'])

	nameservers = set()
	last_line_was_dns_servers_line = False
	for line in output.decode().splitlines():
		if last_line_was_dns_servers_line and is_only_ip(line):
			nameservers.add(line.strip())

		if 'DNS Servers:' in line:
			last_line_was_dns_servers_line = True
			nameservers.add(line.split('DNS Servers:')[1].strip())
		else:
			last_line_was_dns_servers_line = False
	return nameservers


def is_only_ip(line: str) -> bool:
	try:
		IPy.IP(line.strip())
		return True
	except ValueError:
		return False


def get_all_ip_addresses() -> List[str]:
	ip_addresses = []
	for interface in netifaces.interfaces():
		# Skip the loopback device.
		if interface == 'lo':
			continue
		ip_addresses += get_ipv4_addresses(interface)
		ip_addresses += get_ipv6_addresses(interface)
	return ip_addresses


def get_ipv4_addresses(interface: str) -> List[str]:
	short_addresses = []
	if netifaces.AF_INET in netifaces.ifaddresses(interface):
		ipv4_addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET]
		for ipv4_address in ipv4_addresses:
			short_addresses.append(ipv4_address['addr'])
	return short_addresses


def get_ipv6_addresses(interface: str) -> List[str]:
	short_addresses = []
	if netifaces.AF_INET6 in netifaces.ifaddresses(interface):
		ipv6_addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET6]
		for ipv6_address in ipv6_addresses:
			# Skip link-local addresses (see https://superuser.com/a/99753 ).
			if '%' not in ipv6_address['addr']:
				short_addresses.append(ipv6_address['addr'])
	return short_addresses


def ips2name(addrs: Iterable[str]) -> str:
	for addr in addrs:
		fqdn = socket.getfqdn(addr)
		domainname = get_ucs_domainname_from_fqdn(fqdn)
		if domainname:
			return domainname
	return ""


def get_ucs_domainname_from_fqdn(fqdn: str) -> str:
	try:
		domainname = fqdn.split('.', 1)[1]
		# Check if the _domaincontroller_master._tcp record exists, to ensure
		# that this is an UCS domain.
		resolver = dns.resolver.Resolver()
		resolver.query('_domaincontroller_master._tcp.%s' % (domainname,), 'SRV')
	except Exception:
		return ""
	return domainname
