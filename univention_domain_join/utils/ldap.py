#!/usr/bin/env python3
#
# Univention Domain Join
#
# Copyright 2017-2022 Univention GmbH
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

import pipes
import subprocess
from socket import gethostname

from ldap.filter import filter_format


def authenticate_admin(dc_ip: str, admin_username: str, admin_pw: str) -> None:
	ldap_command = ' echo {1} > /dev/shm/{0}domain-join; chmod 600 /dev/shm/{0}domain-join; kinit --password-file=/dev/shm/{0}domain-join {0}'.format(pipes.quote(admin_username), pipes.quote(admin_pw))
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (admin_username, dc_ip), ldap_command],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(admin_pw.encode())


def cleanup_authentication(dc_ip: str, admin_username: str, admin_pw: str) -> None:
	ldap_command = 'rm -f /dev/shm/{0}domain-join; kdestroy'.format(pipes.quote(admin_username))
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (admin_username, dc_ip), ldap_command],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(admin_pw.encode())


def is_samba_dc(admin_username: str, admin_pw: str, dc_ip: str, admin_dn: str) -> bool:
	ldap_command = ['ldapsearch', '-QLLL', filter_format('aRecord=%s', [dc_ip]), 'univentionService']
	escaped_ldap_command = ' '.join([pipes.quote(x) for x in ldap_command])
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (admin_username, dc_ip), escaped_ldap_command],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(admin_pw.encode())
	for line in stdout.decode().splitlines():
		if line.endswith('Samba 4'):
			return True
	return False


def get_machines_ldap_dn(dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str) -> str:
	for udm_type in ['computers/ubuntu', 'computers/linux', 'computers/ucc']:
		try:
			return get_machines_ldap_dn_given_the_udm_type(udm_type, dc_ip, admin_username, admin_pw, admin_dn)
		except LookupError:
			pass
	raise LookupError(dc_ip)


def get_machines_udm_type(dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str) -> str:
	for udm_type in ['computers/ubuntu', 'computers/linux', 'computers/ucc']:
		try:
			get_machines_ldap_dn_given_the_udm_type(udm_type, dc_ip, admin_username, admin_pw, admin_dn)
			return udm_type
		except LookupError:
			pass
	raise LookupError(dc_ip)


def get_machines_ldap_dn_given_the_udm_type(udm_type: str, dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str) -> str:
	hostname = gethostname()
	udm_command = ['/usr/sbin/udm', udm_type, 'list', '--binddn', admin_dn, '--bindpwdfile', '/dev/shm/%sdomain-join' % (admin_username,), '--filter', 'name=%s' % (hostname,)]
	escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (admin_username, dc_ip), escaped_udm_command],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(admin_pw.encode())
	for line in stdout.splitlines():
		if b"dn:" == line[0:3].lower():
			machines_ldap_dn = line[3:].strip()
			return machines_ldap_dn.decode()
	raise LookupError(hostname)
