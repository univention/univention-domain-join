#!/usr/bin/env python
#
# Univention Domain Join
#
# Copyright 2017-2018 Univention GmbH
#
# http://www.univention.de/
#
# All rights reserved.
#
# The source code of this program is made available
# under the terms of the GNU Affero General Public License version 3
# (GNU AGPL V3) as published by the Free Software Foundation.
#
# Binary versions of this program provided by Univention to you as
# well as other copyrighted, protected or trademarked materials like
# Logos, graphics, fonts, specific documentations and configurations,
# cryptographic keys etc. are subject to a license agreement between
# you and Univention and not subject to the GNU AGPL V3.
#
# In the case you use this program under the terms of the GNU AGPL V3,
# the program is provided in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License with the Debian GNU/Linux or Univention distribution in file
# /usr/share/common-licenses/AGPL-3; if not, see
# <http://www.gnu.org/licenses/>.

import IPy
import dns.resolver
import netifaces
import os
import socket
import subprocess

OUTPUT_SINK = open(os.devnull, 'w')


def get_master_ip_through_dns(domain):
	resolver = dns.resolver.Resolver()
	try:
		response = resolver.query('_domaincontroller_master._tcp.%s.' % (domain,), 'SRV')
		master_fqdn = response[0].target.canonicalize().split(1)[0].to_text()
	except:
		return None
	return socket.gethostbyname(master_fqdn)


def get_ucs_domainname():
	domainname = get_ucs_domainname_via_local_configuration()
	if not domainname:
		domainname = get_ucs_domainname_via_reverse_dns()
	if not domainname:
		domainname = get_ucs_domainname_of_dns_server()
	return domainname


def get_ucs_domainname_via_local_configuration():
	try:
		domainname = socket.getfqdn().split('.', 1)[1]
	except:
		return None
	return domainname


def get_ucs_domainname_via_reverse_dns():
	ip_addresses = get_all_ip_addresses()
	possible_ucs_domainnames = set()
	for ip_address in ip_addresses:
		domainname = get_ucs_domainname_from_fqdn(socket.getfqdn(ip_address))
		if domainname:
			possible_ucs_domainnames.add(domainname)
	if len(possible_ucs_domainnames) == 1:
		return possible_ucs_domainnames.pop()
	return None


def get_ucs_domainname_of_dns_server():
	nameservers = get_nameservers()
	possible_ucs_domainnames = set()
	for nameserver in nameservers:
		domainname = get_ucs_domainname_from_fqdn(socket.getfqdn(nameserver))
		if domainname:
			possible_ucs_domainnames.add(domainname)
	if len(possible_ucs_domainnames) == 1:
		return possible_ucs_domainnames.pop()
	return None


def get_nameservers():
	output = subprocess.check_output(['systemd-resolve', '--status'])

	nameservers = set()
	last_line_was_dns_servers_line = False
	for line in output.splitlines():
		if last_line_was_dns_servers_line and is_only_ip(line):
			nameservers.add(line.strip())

		if 'DNS Servers:' in line:
			last_line_was_dns_servers_line = True
			nameservers.add(line.split('DNS Servers:')[1].strip())
		else:
			last_line_was_dns_servers_line = False
	return nameservers


def is_only_ip(line):
	try:
		IPy.IP(line.strip())
		return True
	except ValueError:
		return False


def get_all_ip_addresses():
	ip_addresses = []
	for interface in netifaces.interfaces():
		# Skip the loopback device.
		if interface == 'lo':
			continue
		ip_addresses += get_ipv4_addresses(interface)
		ip_addresses += get_ipv6_addresses(interface)
	return ip_addresses


def get_ipv4_addresses(interface):
	short_addresses = []
	if netifaces.AF_INET in netifaces.ifaddresses(interface):
		ipv4_addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET]
		for ipv4_address in ipv4_addresses:
			short_addresses.append(ipv4_address['addr'])
	return short_addresses


def get_ipv6_addresses(interface):
	short_addresses = []
	if netifaces.AF_INET6 in netifaces.ifaddresses(interface):
		ipv6_addresses = netifaces.ifaddresses(interface)[netifaces.AF_INET6]
		for ipv6_address in ipv6_addresses:
			# Skip link-local addresses (see https://superuser.com/a/99753 ).
			if '%' not in ipv6_address['addr']:
				short_addresses.append(ipv6_address['addr'])
	return short_addresses


def get_ucs_domainname_from_fqdn(fqdn):
	try:
		domainname = fqdn.split('.', 1)[1]
		# Check if the _domaincontroller_master._tcp record exists, to ensure
		# that this is an UCS domain.
		resolver = dns.resolver.Resolver()
		resolver.query('_domaincontroller_master._tcp.%s' % (domainname,), 'SRV')
	except:
		return None
	return domainname
