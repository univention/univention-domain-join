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

import pipes
import subprocess

from univention_domain_join.utils.general import execute_as_root


def get_machines_ldap_dn(ldap_master, master_username, master_pw):
	for udm_type in ['computers/ubuntu', 'computers/linux', 'computers/ucc']:
		machines_ldap_dn = get_machines_ldap_dn_given_the_udm_type(udm_type, ldap_master, master_username, master_pw)
		if machines_ldap_dn:
			return machines_ldap_dn
	return None


def get_machines_udm_type(ldap_master, master_username, master_pw):
	for udm_type in ['computers/ubuntu', 'computers/linux', 'computers/ucc']:
		machines_ldap_dn = get_machines_ldap_dn_given_the_udm_type(udm_type, ldap_master, master_username, master_pw)
		if machines_ldap_dn:
			return udm_type
	return None


@execute_as_root
def get_machines_ldap_dn_given_the_udm_type(udm_type, ldap_master, master_username, master_pw):
	hostname = subprocess.check_output(['hostname', '-s']).strip()
	udm_command = ['/usr/sbin/udm', udm_type, 'list', '--filter', 'name=%s' % (hostname,)]
	escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_master), escaped_udm_command],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(master_pw)

	for line in stdout.splitlines():
		if "dn:" == line[0:3].lower():
			machines_ldap_dn = line[3:].strip()
			return machines_ldap_dn
	return None
