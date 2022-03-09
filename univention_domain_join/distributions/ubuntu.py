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
import time

from univention_domain_join.join_steps.dns_configurator import DnsConfigurator
from univention_domain_join.join_steps.kerberos_configurator import KerberosConfigurator
from univention_domain_join.join_steps.ldap_configurator import LdapConfigurator
from univention_domain_join.join_steps.login_manager_configurator import LoginManagerConfigurator
from univention_domain_join.join_steps.pam_configurator import PamConfigurator
from univention_domain_join.join_steps.sssd_configurator import SssdConfigurator
from univention_domain_join.utils import ldap
from univention_domain_join.utils.general import execute_as_root, name_is_resolvable

userinfo_logger = logging.getLogger('userinfo')


class DomainJoinException(Exception):
	pass


class DcResolveException(Exception):
	pass


class Joiner(object):
	def __init__(self, ucr_variables, admin_username, admin_pw, dc_ip, skip_login_manager, force_ucs_dns):
		self.admin_username = admin_username
		self.admin_pw = admin_pw
		self.dc_ip = dc_ip
		self.skip_login_manager = skip_login_manager
		self.force_ucs_dns = force_ucs_dns
		self.domain = ucr_variables['domainname']
		self.nameservers = [
			ucr_variables['nameserver1'] if ucr_variables['nameserver1'] != "''" else '',
			ucr_variables['nameserver2'] if ucr_variables['nameserver2'] != "''" else '',
			ucr_variables['nameserver3'] if ucr_variables['nameserver3'] != "''" else ''
		]
		self.ldap_master = ucr_variables['ldap_master']
		self.ldap_base = ucr_variables['ldap_base']
		self.ldap_server_name = ucr_variables['ldap_server_name']
		self.kerberos_realm = ucr_variables['kerberos_realm']

	def check_if_join_is_possible_without_problems(self):
		if not self.skip_login_manager and LoginManagerConfigurator().configuration_conflicts():
			userinfo_logger.critical(
				'Joining the UCS domain is not safely possible.\n'
				'Please resolve all problems and run this tool again.'
			)
			raise DomainJoinException()

	def create_backup_of_config_files(self):
		backup_dir = self.create_backup_dir()
		if self.force_ucs_dns:
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
			if self.force_ucs_dns:
				userinfo_logger.info('changing network/dns configuration as requested.')
				DnsConfigurator(self.nameservers, self.domain).configure_dns()
			# check if we can resolve the ldap_server_name and ldap_master
			if not name_is_resolvable(self.ldap_master):
				raise DcResolveException('The UCS master name %s can not be resolved, please check your DNS settings' % self.ldap_master)
			if not name_is_resolvable(self.ldap_server_name):
				raise DcResolveException('The UCS DC name %s can not be resolved, please check your DNS settings' % self.ldap_server_name)
			ldap.authenticate_admin(self.dc_ip, self.admin_username, self.admin_pw)
			admin_dn = LdapConfigurator().get_admin_dn(self.dc_ip, self.admin_username, self.admin_pw, self.ldap_base)
			is_samba_dc = ldap.is_samba_dc(self.admin_username, self.admin_pw, self.dc_ip, admin_dn)
			LdapConfigurator().configure_ldap(self.dc_ip, self.ldap_server_name, self.admin_username, self.admin_pw, self.ldap_base, admin_dn)
			SssdConfigurator().setup_sssd(self.dc_ip, self.ldap_master, self.ldap_server_name, self.admin_username, self.admin_pw, self.ldap_base, self.kerberos_realm, admin_dn, is_samba_dc)
			PamConfigurator().setup_pam()
			if not self.skip_login_manager:
				LoginManagerConfigurator().enable_login_with_foreign_usernames()
			KerberosConfigurator().configure_kerberos(self.kerberos_realm, self.ldap_master, self.ldap_server_name, is_samba_dc, self.dc_ip)
			# TODO: Stop avahi service to prevent problems with sssd?
			userinfo_logger.info('The domain join was successful.')
			userinfo_logger.info('Please reboot the system.')
		finally:
			ldap.cleanup_authentication(self.dc_ip, self.admin_username, self.admin_pw)
