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

from shutil import copyfile
import logging
import os
import pipes
import stat
import subprocess

from univention_domain_join.join_steps.root_certificate_provider import RootCertificateProvider
from univention_domain_join.utils.general import execute_as_root
from univention_domain_join.utils.ldap import get_machines_ldap_dn
from univention_domain_join.utils.ldap import get_machines_udm_type

userinfo_logger = logging.getLogger('userinfo')

OUTPUT_SINK = open(os.devnull, 'w')


class LdapConfigutationException(Exception):
	pass


class ConflictChecker(object):
	def ldap_conf_exists(self):
		if os.path.isfile('/etc/ldap/ldap.conf'):
			userinfo_logger.warn('Warning: /etc/ldap/ldap.conf already exists.')
			return True
		return False


class LdapConfigurator(ConflictChecker):
	@execute_as_root
	def backup(self, backup_dir):
		if self.ldap_conf_exists():
			os.makedirs(os.path.join(backup_dir, 'etc/ldap'))
			copyfile(
				'/etc/ldap/ldap.conf',
				os.path.join(backup_dir, 'etc/ldap/ldap.conf')
			)

	def configure_ldap(self, ldap_master, master_username, master_pw, ldap_base, admin_dn):
		RootCertificateProvider().provide_ucs_root_certififcate(ldap_master)
		password = self.random_password()
		self.modify_old_entry_or_add_machine_to_ldap(password, ldap_master, master_username, master_pw, ldap_base, admin_dn)
		self.create_ldap_conf_file(ldap_master, ldap_base)
		self.create_machine_secret_file(password)

	def modify_old_entry_or_add_machine_to_ldap(self, password, ldap_master, master_username, master_pw, ldap_base, admin_dn):
		if get_machines_ldap_dn(ldap_master, master_username, master_pw, admin_dn):
			self.modify_machine_in_ldap(password, ldap_master, master_username, master_pw, admin_dn)
		else:
			self.add_machine_to_ldap(password, ldap_master, master_username, master_pw, ldap_base, admin_dn)

	@execute_as_root
	def modify_machine_in_ldap(self, password, ldap_master, master_username, master_pw, admin_dn):
		userinfo_logger.info('Updating old LDAP entry for this machine on the DC master')

		release_id = subprocess.check_output(['lsb_release', '-is']).strip().decode()
		release = subprocess.check_output(['lsb_release', '-rs']).strip().decode()

		udm_command = [
			'/usr/sbin/udm',
			get_machines_udm_type(ldap_master, master_username, master_pw, admin_dn),
			'modify',
			'--binddn','%s' % (admin_dn,),
			'--bindpwdfile','/dev/shm/%sdomain-join' % (master_username,),
			'--dn', get_machines_ldap_dn(ldap_master, master_username, master_pw, admin_dn),
			'--set', 'password=%s' % (password,),
			'--set', 'operatingSystem=%s' % (release_id,),
			'--set', 'operatingSystemVersion=%s' % (release,)
		]
		escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
		return escaped_udm_command
		ssh_process = subprocess.Popen(
			['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_master), escaped_udm_command],
			stdin=subprocess.PIPE, stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)
		ssh_process.communicate(master_pw.encode())
		if ssh_process.returncode != 0:
			userinfo_logger.critical('Updating the old LDAP entry for this computer failed.')
			raise LdapConfigutationException()


	@execute_as_root
	def add_machine_to_ldap(self, password, ldap_master, master_username, master_pw, ldap_base, admin_dn):
		userinfo_logger.info('Adding LDAP entry for this machine on the DC master')
		hostname = subprocess.check_output(['hostname', '-s']).strip().decode()
		release_id = subprocess.check_output(['lsb_release', '-is']).strip().decode()
		release = subprocess.check_output(['lsb_release', '-rs']).strip().decode()

		# TODO: Also add MAC address. Which NIC's address should be used?
		udm_command = [
			'/usr/sbin/udm', 'computers/ubuntu', 'create',
			'--binddn','%s' % (admin_dn,),
			'--bindpwdfile','/dev/shm/%sdomain-join' % (master_username,),
			'--position', 'cn=computers,%s' % (ldap_base,),
			'--set', 'name=%s' % (hostname,),
			'--set', 'password=%s' % (password,),
			'--set', 'operatingSystem=%s' % (release_id,),
			'--set', 'operatingSystemVersion=%s' % (release,)
		]
		escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
		userinfo_logger.info('%s' % escaped_udm_command)
		ssh_process = subprocess.Popen(
			['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_master), escaped_udm_command],
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
		)
		stdout, _ = ssh_process.communicate(master_pw.encode())

		if ssh_process.returncode != 0 or stdout.decode().startswith('E: '):
			userinfo_logger.critical('Adding an LDAP object for this computer didn\'t work.')
			userinfo_logger.critical('%s' % stdout)
			raise LdapConfigutationException()

	@execute_as_root
	def get_admin_dn(self, ldap_master, master_username, master_pw, ldap_base):
		userinfo_logger.info('Getting the DN of the Administrator ')
		ldap_command = 'ldapsearch -QLLL uid=%s dn' % (pipes.quote(master_username),)
		ssh_process = subprocess.Popen(
			['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_master), ldap_command],
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
		)
		stdout, _ = ssh_process.communicate(master_pw.encode())
		admin_dn = stdout.decode().strip().split(': ', 1)[1]
		return admin_dn

	@execute_as_root
	def create_ldap_conf_file(self, ldap_master, ldap_base):
		userinfo_logger.info('Writing /etc/ldap/ldap.conf ')

		ldap_conf = \
			"TLS_CACERT /etc/univention/ssl/ucsCA/CAcert.pem\n" \
			"URI ldap://%s:7389\n" \
			"BASE %s\n" \
			% (ldap_master, ldap_base)

		with open('/etc/ldap/ldap.conf', 'w') as conf_file:
			conf_file.write(ldap_conf)

	@execute_as_root
	def create_machine_secret_file(self, password):
		userinfo_logger.info('Writing /etc/machine.secret ')

		with open('/etc/machine.secret', 'w') as secret_file:
			secret_file.write(password)
		os.chmod('/etc/machine.secret', stat.S_IREAD)

	def random_password(self, length=20):
		chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[]^_`{|}~'
		password = ''
		for _ in range(length):
			password += chars[ord(os.urandom(1)) % len(chars)]
		return password
