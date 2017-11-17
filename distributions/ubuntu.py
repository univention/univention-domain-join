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
		pass

	def create_backup_of_config_files(self):
		pass

	def join_domain(self, force=False):
		self.configure_ldap(force)
		self.configure_sssd(force)
		self.configure_pam(force)
		self.configure_login(force)
		self.configure_kerberos(force)
		# TODO: Stop avahi service like Jan-Christoph does?!

	def configure_ldap(self, force=False):
		if force or not LdapConfigurator().ldap_configured(self.master_ip, self.master_pw, self.ldap_base):
			LdapConfigurator().configure_ldap(self.master_ip, self.master_pw, self.ldap_master, self.ldap_base)
		else:
			print('The LDAP seems to be configured already. Skipping this step.')

	def configure_sssd(self, force=False):
		if force or not SssdConfigurator().sssd_configured():
			SssdConfigurator().setup_sssd(self.master_ip, self.ldap_master, self.ldap_base, self.kerberos_realm)
		else:
			print('sssd seems to be configured already. Skipping this step.')

	def configure_pam(self, force=False):
		if force or not PamConfigurator().pam_configured():
			PamConfigurator().setup_pam()
		else:
			print('PAM seems to be configured already. Skipping this step.')

	def configure_login(self, force=False):
		if force or not LoginManagerConfigurator().login_manager_configured():
			if LoginManagerConfigurator().login_manager_compatible():
				LoginManagerConfigurator().enable_login_with_foreign_usernames()
			else:
				print('Warning: The login manager remains unconfigured.')
		else:
			print('PAM seems to be configured already. Skipping this step.')

	def configure_kerberos(self, force=False):
		if force or not KerberosConfigurator().kerberos_configured(self.ldap_master):
			KerberosConfigurator().configure_kerberos(self.kerberos_realm, self.master_ip, self.ldap_master)
		else:
			print('Kerberos seems to be configured already. Skipping this step.')

	def show_join_status(self):
		if (
			LdapConfigurator().ldap_configured(self.master_ip, self.master_pw, self.ldap_base) and
			SssdConfigurator().sssd_configured() and
			PamConfigurator().pam_configured() and
			LoginManagerConfigurator().login_manager_configured() and
			KerberosConfigurator().kerberos_configured(self.ldap_master)
		):
			print('This client has been joined into your UCS domain.')
		else:
			print('This client has not fully joined an UCS domain.')
