import argparse
import getpass
import os
import subprocess

from join_steps.kerberos_configurator import KerberosConfigurator
from join_steps.ldap_configurator import LdapConfigurator
from join_steps.login_manager_configurator import LoginManagerConfigurator
from join_steps.pam_configurator import PamConfigurator
from join_steps.sssd_configurator import SssdConfigurator

OUTPUT_SINK = open(os.devnull, 'w')

# TODO: Make sure dependent packets are installed in the Debian package.


class UcsJoiner(object):
	def __init__(self, master_ip):
		self.check_if_this_is_run_as_root()
		self.check_if_dns_is_set_up_correctly(master_ip)
		self.master_pw = self.get_masters_root_password(master_ip)

		masters_ucr_variables = self.get_ucr_variables_from_master(master_ip, self.master_pw)

		self.master_ip = master_ip
		self.ldap_master = masters_ucr_variables['ldap_master']
		self.ldap_base = masters_ucr_variables['ldap_base']
		self.kerberos_realm = masters_ucr_variables['kerberos_realm']

	def check_if_this_is_run_as_root(self):
		assert os.geteuid() == 0, 'This tool must be run as the root user.'

	def check_if_dns_is_set_up_correctly(self, master_ip):
		master_dns_works = 0 == subprocess.call(
			['host', master_ip], stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)
		assert master_dns_works, 'The DC master is not set as DNS server.'

	def get_masters_root_password(self, master_ip):
		return getpass(prompt='Please enter the password for root@%s:' % (master_ip,))
		# TODO: Check if password works.

	def get_ucr_variables_from_master(self, master_ip, master_pw):
		masters_ucr_output = subprocess.check_output(
			['ssh', 'root@%s' % (master_ip,), 'ucr shell | grep -v ^hostname='],
		).splitlines()
		ucr_variables = {}
		for raw_ucr_variable in masters_ucr_output:
			key, value = raw_ucr_variable.split('=', 1)
			ucr_variables[key] = value
		return ucr_variables

	def join_domain(self, force=False):
		self.configure_ldap(force)
		self.configure_sssd(force)
		self.configure_pam(force)
		self.configure_login(force)
		self.configure_kerberos(force)
		# TODO: Stop avahi service like Jan-Christoph does?!

	def configure_ldap(self, force=False):
		if force or not LdapConfigurator().ldap_configured(self.master_ip, self.ldap_base):
			LdapConfigurator().configure_ldap(self.master_ip, self.ldap_master, self.ldap_base)
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
			LdapConfigurator().ldap_configured(self.master_ip, self.ldap_base) and
			SssdConfigurator().sssd_configured() and
			PamConfigurator().pam_configured() and
			LoginManagerConfigurator().login_manager_configured() and
			KerberosConfigurator().kerberos_configured(self.ldap_master)
		):
			print('This client has been joined into your UCS domain.')
		else:
			print('This client has not fully joined an UCS domain.')


if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='Tool for checking the join status and execute a join of an Ubuntu client in an UCS domain.'
	)
	parser.add_argument('--join', action='store_true', help='Join an UCS domain.')
	parser.add_argument('--force', action='store_true', help='Force the execution of the join steps, even if they seem to have been executed before.')
	parser.add_argument('MASTER_IP', help='IP of the DC master.')

	ucs_joiner = UcsJoiner('10.200.36.30')
	ucs_joiner.join_domain()
