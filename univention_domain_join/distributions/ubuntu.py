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

import logging
import os
import time

from univention_domain_join.join_steps.dns_configurator import DnsConfigurator
from univention_domain_join.join_steps.kerberos_configurator import KerberosConfigurator
from univention_domain_join.join_steps.ldap_configurator import LdapConfigurator
from univention_domain_join.join_steps.login_manager_configurator import LoginManagerConfigurator
from univention_domain_join.join_steps.pam_configurator import PamConfigurator
from univention_domain_join.join_steps.sssd_configurator import SssdConfigurator
import univention_domain_join.utils.ldap as ldap

from univention_domain_join.utils.general import execute_as_root


userinfo_logger = logging.getLogger('userinfo')


class DomainJoinException(Exception):
	pass


class Joiner(object):
	def __init__(self, masters_ucr_variables, master_ip, master_username, master_pw, dc_ip, skip_login_manager, skip_network_settings):
		self.master_username = master_username
		self.master_pw = master_pw
		self.master_ip = master_ip
		self.dc_ip = dc_ip
		self.skip_login_manager = skip_login_manager
		self.skip_network_settings = skip_network_settings
		self.domain = masters_ucr_variables[b'domainname'].decode()
		self.nameservers = [
			masters_ucr_variables[b'nameserver1'].decode() if masters_ucr_variables[b'nameserver1'] != b"''" else '',
			masters_ucr_variables[b'nameserver2'].decode() if masters_ucr_variables[b'nameserver2'] != b"''" else '',
			masters_ucr_variables[b'nameserver3'].decode() if masters_ucr_variables[b'nameserver3'] != b"''" else ''
		]
		self.ldap_master = masters_ucr_variables[b'ldap_master'].decode()
		self.ldap_dc = masters_ucr_variables[b'ldap_server_name'].decode()
		self.ldap_base = masters_ucr_variables[b'ldap_base'].decode()
		userinfo_logger.info(self.ldap_base)
		self.kerberos_realm = masters_ucr_variables[b'kerberos_realm'].decode()

	def check_if_join_is_possible_without_problems(self):
		if not self.skip_login_manager and LoginManagerConfigurator().configuration_conflicts():
			userinfo_logger.critical(
				'Joining the UCS domain is not safely possible.\n'
				'Please resolve all problems and run this tool again.'
			)
			raise DomainJoinException()

	def create_backup_of_config_files(self):
		backup_dir = self.create_backup_dir()
		if not self.skip_network_settings:
			DnsConfigurator(self.nameservers, self.domain).backup(backup_dir)
		LdapConfigurator().backup(backup_dir)
		SssdConfigurator().backup(backup_dir)
		PamConfigurator().backup(backup_dir)
		if not self.skip_login_manager:
			LoginManagerConfigurator().backup(backup_dir)
		KerberosConfigurator().backup(backup_dir)

		userinfo_logger.info('Created a backup of all configuration files, that will be modified at \'%s\'.' % backup_dir)

	@execute_as_root
	def create_backup_dir(self):
		backup_dir = os.path.join('/var/univention-backup', time.strftime("%Y%m%d%H%M%S_domain-join", time.gmtime()))
		os.makedirs(backup_dir)
		return backup_dir

	def join_domain(self):
		try:
			if not self.skip_network_settings:
				DnsConfigurator(self.nameservers, self.domain).configure_dns()
			else:
				userinfo_logger.info('Skipping network/dns configuration as requested.')
			ldap.authenticate_admin(self.ldap_dc, self.master_username, self.master_pw)
			admin_dn = LdapConfigurator().get_admin_dn(self.ldap_dc, self.master_username, self.master_pw, self.ldap_base)
			is_samba_dc = ldap.is_samba_dc(self.ldap_dc, self.master_username, self.master_pw, self.dc_ip, admin_dn)
			LdapConfigurator().configure_ldap(self.ldap_dc, self.master_username, self.master_pw, self.ldap_base, admin_dn)
			SssdConfigurator().setup_sssd(self.master_ip, self.ldap_master, self.master_username, self.master_pw, self.ldap_base, self.kerberos_realm, self.ldap_dc, self.dc_ip, admin_dn)
			PamConfigurator().setup_pam()
			if not self.skip_login_manager:
				LoginManagerConfigurator().enable_login_with_foreign_usernames()
			KerberosConfigurator().configure_kerberos(self.kerberos_realm, self.master_ip, self.ldap_master, self.ldap_dc, self.dc_ip, is_samba_dc)
			# TODO: Stop avahi service to prevent problems with sssd?
			userinfo_logger.info('The domain join was successful.')
			userinfo_logger.info('Please reboot the system.')
		finally:
			ldap.cleanup_authentication(self.ldap_dc, self.master_username, self.master_pw)
