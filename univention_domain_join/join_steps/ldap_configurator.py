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
# n the case you use this program under the terms of the GNU AGPL V3,
# the program is provided in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License with the Debian GNU/Linux or Univention distribution in file
# /usr/share/common-licenses/AGPL-3; if not, see
# <http://www.gnu.org/licenses/>.

import logging
import os
import stat
import subprocess
from shutil import copyfile

from univention_domain_join.join_steps.root_certificate_provider import RootCertificateProvider
from univention_domain_join.utils.general import execute_as_root, ssh
from univention_domain_join.utils.ldap import PW, get_machines_ldap_dn, get_machines_udm_type

userinfo_logger = logging.getLogger('userinfo')


class LdapConfigutationException(Exception):
	pass


class ConflictChecker(object):
	def ldap_conf_exists(self) -> bool:
		if os.path.isfile('/etc/ldap/ldap.conf'):
			userinfo_logger.warn('Warning: /etc/ldap/ldap.conf already exists.')
			return True
		return False


class LdapConfigurator(ConflictChecker):
	@execute_as_root
	def backup(self, backup_dir: str) -> None:
		if self.ldap_conf_exists():
			os.makedirs(os.path.join(backup_dir, 'etc/ldap'), exist_ok=True)
			copyfile(
				'/etc/ldap/ldap.conf',
				os.path.join(backup_dir, 'etc/ldap/ldap.conf')
			)

	def configure_ldap(self, dc_ip: str, ldap_server_name: str, admin_username: str, admin_pw: str, ldap_base: str, admin_dn: str) -> None:
		RootCertificateProvider().provide_ucs_root_certififcate(dc_ip)
		password = self.random_password()
		self.modify_old_entry_or_add_machine_to_ldap(password, dc_ip, admin_username, admin_pw, ldap_base, admin_dn)
		self.create_ldap_conf_file(ldap_server_name, ldap_base)
		self.create_machine_secret_file(password)

	def modify_old_entry_or_add_machine_to_ldap(self, password: str, dc_ip: str, admin_username: str, admin_pw: str, ldap_base: str, admin_dn: str) -> None:
		try:
			get_machines_ldap_dn(dc_ip, admin_username, admin_pw, admin_dn)
		except LookupError:
			self.add_machine_to_ldap(password, dc_ip, admin_username, admin_pw, ldap_base, admin_dn)
		else:
			self.modify_machine_in_ldap(password, dc_ip, admin_username, admin_pw, admin_dn)

	def modify_machine_in_ldap(self, password: str, dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str) -> None:
		userinfo_logger.info('Updating old LDAP entry for this machine on the UCS DC')

		release_id = subprocess.check_output(['lsb_release', '-is']).strip().decode()
		release = subprocess.check_output(['lsb_release', '-rs']).strip().decode()

		udm_command = [
			'/usr/sbin/udm',
			get_machines_udm_type(dc_ip, admin_username, admin_pw, admin_dn),
			'modify',
			'--binddn', admin_dn,
			'--bindpwdfile', PW(admin_username),
			'--dn', get_machines_ldap_dn(dc_ip, admin_username, admin_pw, admin_dn),
			'--set', 'password=%s' % (password,),
			'--set', 'operatingSystem=%s' % (release_id,),
			'--set', 'operatingSystemVersion=%s' % (release,)
		]
		ssh_process = ssh(admin_username, admin_pw, dc_ip, udm_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		ssh_process.communicate()
		if ssh_process.returncode != 0:
			userinfo_logger.critical('Updating the old LDAP entry for this computer failed.')
			raise LdapConfigutationException()

	def add_machine_to_ldap(self, password: str, dc_ip: str, admin_username: str, admin_pw: str, ldap_base: str, admin_dn: str) -> None:
		userinfo_logger.info('Adding LDAP entry for this machine on the UCS DC')
		hostname = subprocess.check_output(['hostname', '-s']).strip().decode()
		release_id = subprocess.check_output(['lsb_release', '-is']).strip().decode()
		release = subprocess.check_output(['lsb_release', '-rs']).strip().decode()
		# TODO: Also add MAC address. Which NIC's address should be used?
		udm_command = [
			'/usr/sbin/udm', 'computers/ubuntu', 'create',
			'--binddn', admin_dn,
			'--bindpwdfile', PW(admin_username),
			'--position', 'cn=computers,%s' % (ldap_base,),
			'--set', 'name=%s' % (hostname,),
			'--set', 'password=%s' % (password,),
			'--set', 'operatingSystem=%s' % (release_id,),
			'--set', 'operatingSystemVersion=%s' % (release,)
		]
		ssh_process = ssh(admin_username, admin_pw, dc_ip, udm_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		stdout, _ = ssh_process.communicate()
		if ssh_process.returncode != 0 or stdout.decode().startswith('E: '):
			userinfo_logger.critical('Adding an LDAP object for this computer didn\'t work.')
			userinfo_logger.critical(stdout.decode())
			raise LdapConfigutationException()

	def get_admin_dn(self, dc_ip: str, admin_username: str, admin_pw: str, ldap_base: str) -> str:
		userinfo_logger.info('Getting the DN of the Administrator ')
		ldap_command = ['ldapwhoami', '-QY', 'GSSAPI']
		ssh_process = ssh(admin_username, admin_pw, dc_ip, ldap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		stdout, stderr = ssh_process.communicate()
		if ssh_process.returncode != 0:
			userinfo_logger.critical('get admin DN failed with: {}'.format(stderr.decode()))
			raise LdapConfigutationException('get admin DN failed with: {}'.format(stderr.decode()))
		dn, _, admin_dn = stdout.decode().strip().partition(':')
		assert dn == "dn", stdout
		return admin_dn

	@execute_as_root
	def create_ldap_conf_file(self, ldap_server_name: str, ldap_base: str) -> None:
		userinfo_logger.info('Writing /etc/ldap/ldap.conf ')
		ldap_conf = \
			"TLS_CACERT /etc/univention/ssl/ucsCA/CAcert.pem\n" \
			"URI ldap://%s:7389\n" \
			"BASE %s\n" % (ldap_server_name, ldap_base)

		with open('/etc/ldap/ldap.conf', 'w') as conf_file:
			conf_file.write(ldap_conf)

	@execute_as_root
	def create_machine_secret_file(self, password: str) -> None:
		userinfo_logger.info('Writing /etc/machine.secret ')
		with open('/etc/machine.secret', 'w') as secret_file:
			secret_file.write(password)
		os.chmod('/etc/machine.secret', stat.S_IREAD)

	def random_password(self, length: int = 20) -> str:
		chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[]^_`{|}~'
		password = ''
		for _ in range(length):
			password += chars[ord(os.urandom(1)) % len(chars)]
		return password
