import dns.resolver
import time
import os

from join_steps.kerberos_configurator import KerberosConfigurator
from join_steps.ldap_configurator import LdapConfigurator
from join_steps.login_manager_configurator import LoginManagerConfigurator
from join_steps.pam_configurator import PamConfigurator
from join_steps.sssd_configurator import SssdConfigurator


class Joiner(object):
	def __init__(self, masters_ucr_variables, master, master_pw, skip_login_manager):
		self.check_if_this_is_run_as_root()

		self.master_pw = master_pw
		self.master_ip = self.get_master_ip(master)
		self.skip_login_manager = skip_login_manager
		self.ldap_master = masters_ucr_variables['ldap_master']
		self.ldap_base = masters_ucr_variables['ldap_base']
		self.kerberos_realm = masters_ucr_variables['kerberos_realm']

	def check_if_this_is_run_as_root(self):
		assert os.geteuid() == 0, 'This tool must be run as the root user.'

	def get_master_ip(self, master):
		resolver = dns.resolver.Resolver()
		response = resolver.query(master, 'A')
		return response[0].address

	def check_if_join_is_possible_without_problems(self):
		if not self.skip_login_manager and LoginManagerConfigurator().configuration_conflicts():
			raise Exception(
				'Joining the UCS is not safely possible.\n'
				'Please resolve all problems and run this tool again.'
			)

	def create_backup_of_config_files(self):
		backup_dir = self.create_backup_dir()

		LdapConfigurator().backup(backup_dir)
		SssdConfigurator().backup(backup_dir)
		PamConfigurator().backup(backup_dir)
		if not self.skip_login_manager:
			LoginManagerConfigurator().backup(backup_dir)
		KerberosConfigurator().backup(backup_dir)

		print('Created a backup of all configuration files, that will be modified at \'%s\'.' % backup_dir)

	def create_backup_dir(self):
		backup_dir = os.path.join('/var/univention-backup', time.strftime("%Y%m%d%H%M%S_domain-join", time.gmtime()))
		os.makedirs(backup_dir)
		return backup_dir

	def join_domain(self):
		LdapConfigurator().configure_ldap(self.ldap_master, self.master_pw, self.ldap_base)
		SssdConfigurator().setup_sssd(self.master_ip, self.ldap_master, self.ldap_base, self.kerberos_realm)
		PamConfigurator().setup_pam()
		if not self.skip_login_manager:
			LoginManagerConfigurator().enable_login_with_foreign_usernames()
		KerberosConfigurator().configure_kerberos(self.kerberos_realm, self.master_ip, self.ldap_master)
		# TODO: Stop avahi service to prevent problems with sssd?
		print('The domain join was successful.')
		print('Please reboot the system.')
