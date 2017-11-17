import os

from join_steps.kerberos_configurator import KerberosConfigurator
from join_steps.ldap_configurator import LdapConfigurator
from join_steps.login_manager_configurator import LoginManagerConfigurator
from join_steps.pam_configurator import PamConfigurator
from join_steps.sssd_configurator import SssdConfigurator


class Joiner(object):
	def __init__(self, masters_ucr_variables, master_ip, master_pw):
		self.check_if_this_is_run_as_root()

		self.master_ip = master_ip
		self.master_pw = master_pw
		self.ldap_master = masters_ucr_variables['ldap_master']
		self.ldap_base = masters_ucr_variables['ldap_base']
		self.kerberos_realm = masters_ucr_variables['kerberos_realm']

	def check_if_this_is_run_as_root(self):
		assert os.geteuid() == 0, 'This tool must be run as the root user.'

	def check_if_join_is_possible_without_problems(self):
		if (
			LdapConfigurator().configuration_conflicts() or
			SssdConfigurator().configuration_conflicts() or
			PamConfigurator().configuration_conflicts() or
			LoginManagerConfigurator().configuration_conflicts() or
			KerberosConfigurator().configuration_conflicts()
		):
			raise Exception('Joining the UCS is not safely possible. Use the --force parameter to ignore this warning.')

	def create_backup_of_config_files(self):
		pass

	def join_domain(self, force=False):
		LdapConfigurator().configure_ldap(self.master_ip, self.master_pw, self.ldap_master, self.ldap_base)
		SssdConfigurator().setup_sssd(self.master_ip, self.ldap_master, self.ldap_base, self.kerberos_realm)
		PamConfigurator().setup_pam()
		LoginManagerConfigurator().enable_login_with_foreign_usernames()
		KerberosConfigurator().configure_kerberos(self.kerberos_realm, self.master_ip, self.ldap_master)
		# TODO: Stop avahi service like Jan-Christoph does?!
