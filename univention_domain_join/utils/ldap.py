#!/usr/bin/env python3
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

import pipes
import subprocess

from univention_domain_join.utils.general import execute_as_root

@execute_as_root
def authenticate_admin(ldap_dc, master_username, master_pw):
	ldap_command = ' echo {1} > /dev/shm/{0}domain-join; chmod 600 /dev/shm/{0}domain-join; kinit --password-file=/dev/shm/{0}domain-join {0}'.format(master_username, master_pw)
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_dc), ldap_command],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(master_pw.encode())

@execute_as_root
def cleanup_authentication(ldap_dc, master_username, master_pw):
	ldap_command = 'rm -f /dev/shm/{0}domain-join; kdestroy'.format(master_username)
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_dc), ldap_command],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(master_pw.encode())

@execute_as_root
def is_samba_dc(ldap_dc, master_username, master_pw, dc_ip, admin_dn):
	ldap_command = ['ldapsearch', '-QLLL', 'aRecord=%s' % (dc_ip), 'univentionService']
	escaped_ldap_command = ' '.join([pipes.quote(x) for x in ldap_command])
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_dc), escaped_ldap_command],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(master_pw.encode())
	for line in stdout.decode().splitlines():
		if line.endswith('Samba 4'):
			return True
	return False

def get_machines_ldap_dn(ldap_master, master_username, master_pw, admin_dn):
	for udm_type in ['computers/ubuntu', 'computers/linux', 'computers/ucc']:
		machines_ldap_dn = get_machines_ldap_dn_given_the_udm_type(udm_type, ldap_master, master_username, master_pw, admin_dn)
		if machines_ldap_dn:
			return machines_ldap_dn
	return None


def get_machines_udm_type(ldap_master, master_username, master_pw, admin_dn):
	for udm_type in ['computers/ubuntu', 'computers/linux', 'computers/ucc']:
		machines_ldap_dn = get_machines_ldap_dn_given_the_udm_type(udm_type, ldap_master, master_username, master_pw, admin_dn)
		if machines_ldap_dn:
			return udm_type
	return None


@execute_as_root
def get_machines_ldap_dn_given_the_udm_type(udm_type, ldap_master, master_username, master_pw, admin_dn):
	hostname = subprocess.check_output(['hostname', '-s']).strip().decode()
	udm_command = ['/usr/sbin/udm', udm_type, 'list', '--binddn', admin_dn, '--bindpwdfile', '/dev/shm/%sdomain-join' %(master_username,),'--filter', 'name=%s' % (hostname,)]
	escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_master), escaped_udm_command],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(master_pw.encode())
	for line in stdout.splitlines():
		if b"dn:" == line[0:3].lower():
			machines_ldap_dn = line[3:].strip()
			return machines_ldap_dn.decode()
	return None
