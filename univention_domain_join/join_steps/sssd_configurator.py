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

import logging
import os
import stat
import subprocess
from shutil import copyfile

from univention_domain_join.join_steps.root_certificate_provider import RootCertificateProvider
from univention_domain_join.utils.general import execute_as_root
from univention_domain_join.utils.ldap import get_machines_ldap_dn

OUTPUT_SINK = open(os.devnull, 'w')

userinfo_logger = logging.getLogger('userinfo')


class ConflictChecker(object):
	def sssd_conf_file_exists(self) -> bool:
		if os.path.isfile('/etc/sssd/sssd.conf'):
			userinfo_logger.warn('Warning: /etc/sssd/sssd.conf already exists.')
			return True
		return False


class SssdConfigurator(ConflictChecker):

	@execute_as_root
	def backup(self, backup_dir: str) -> None:
		if self.sssd_conf_file_exists():
			os.makedirs(os.path.join(backup_dir, 'etc/sssd'))
			copyfile(
				'/etc/sssd/sssd.conf',
				os.path.join(backup_dir, 'etc/sssd/sssd.conf')
			)

	@execute_as_root
	def setup_sssd(self, dc_ip: str, ldap_master: str, ldap_server_name: str, admin_username: str, admin_pw: str, ldap_base: str, kerberos_realm: str, admin_dn: str, is_samba_dc: bool) -> None:
		self.ldap_password = open('/etc/machine.secret').read().strip()
		RootCertificateProvider().provide_ucs_root_certififcate(dc_ip)
		self.write_sssd_conf(dc_ip, ldap_master, ldap_server_name, admin_username, admin_pw, ldap_base, kerberos_realm, admin_dn, is_samba_dc)
		self.configure_sssd()
		self.restart_sssd()

	@execute_as_root
	def write_sssd_conf(self, dc_ip: str, ldap_master: str, ldap_server_name: str, admin_username: str, admin_pw: str, ldap_base: str, kerberos_realm: str, admin_dn: str, is_samba_dc: bool) -> None:
		userinfo_logger.info('Writing /etc/sssd/sssd.conf ')
		if is_samba_dc:
			kpasswd_server = ldap_server_name
		else:
			kpasswd_server = ldap_master
		sssd_conf = \
			'[sssd]\n' \
			'config_file_version = 2\n' \
			'reconnection_retries = 3\n' \
			'sbus_timeout = 30\n' \
			'services = nss, pam, sudo\n' \
			'domains = %(kerberos_realm)s\n' \
			'\n' \
			'[nss]\n' \
			'reconnection_retries = 3\n' \
			'\n' \
			'[pam]\n' \
			'reconnection_retries = 3\n' \
			'\n' \
			'[domain/%(kerberos_realm)s]\n' \
			'auth_provider = krb5\n' \
			'krb5_realm = %(kerberos_realm)s\n' \
			'krb5_server = %(ldap_server_name)s\n' \
			'krb5_kpasswd = %(kpasswd_server)s\n' \
			'id_provider = ldap\n' \
			'ldap_uri = ldap://%(ldap_server_name)s:7389\n' \
			'ldap_search_base = %(ldap_base)s\n' \
			'ldap_tls_reqcert = never\n' \
			'ldap_tls_cacert = /etc/univention/ssl/ucsCA/CAcert.pem\n' \
			'cache_credentials = true\n' \
			'enumerate = true\n' \
			'ldap_default_bind_dn = %(machines_ldap_dn)s\n' \
			'ldap_default_authtok_type = password\n' \
			'ldap_default_authtok = %(ldap_password)s\n' \
			% {
				'kerberos_realm': kerberos_realm,
				'kpasswd_server': kpasswd_server,
				'ldap_base': ldap_base,
				'ldap_server_name': ldap_server_name,
				'ldap_password': self.ldap_password,
				'machines_ldap_dn': get_machines_ldap_dn(dc_ip, admin_username, admin_pw, admin_dn),
			}
		with open('/etc/sssd/sssd.conf', 'w') as conf_file:
			conf_file.write(sssd_conf)
		os.chmod('/etc/sssd/sssd.conf', stat.S_IREAD | stat.S_IWRITE)

	@execute_as_root
	def configure_sssd(self) -> None:
		userinfo_logger.info('Configuring auth config profile for sssd')

		subprocess.check_call(
			['pam-auth-update', '--enable', 'mkhomedir'],
			stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)

	@execute_as_root
	def restart_sssd(self) -> None:
		userinfo_logger.info('Restarting sssd')

		subprocess.check_call(
			['service', 'sssd', 'restart'],
			stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)
