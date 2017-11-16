from __future__ import print_function
import os
import subprocess
import sys

OUTPUT_SINK = open(os.devnull, 'w')


class LoginManagerConfigurationChecker(object):
	def login_manager_compatible(self):
		login_manager = self.determin_used_login_manager()
		if login_manager == 'lightdm':
			return True
		return False

	def login_manager_configured(self):
		login_manager = self.determin_used_login_manager()
		if login_manager == 'lightdm':
			return self.lightdm_config_file_exists()
		elif login_manager == 'lightdm_account_service':
			print('The login won\'t work with your system, because you are using an incompatible login theme.')
			print('Please go to "System Settings" -> "Login Screen (LightDM)" and set your login theme to "Classic".')
		else:
			print('Can\'t enable login with the login manager of your system.')
			print('Please use LightDM for full compatibility with UCS.')
		return False

	def lightdm_config_file_exists(self):
		return os.path.isfile('/etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf')

	def determin_used_login_manager(self):
		with open('/etc/X11/default-display-manager', 'r') as login_manager_file:
			login_manager = os.path.basename(login_manager_file.read()).strip()

		# The lightdm config files will be ignored with a certain setup (e.g. in
		# Kubuntu 14.04), so check for that.
		if login_manager == 'lightdm' and self.kde_greeter_is_installed():
			if not self.theme_with_accountsservice_is_ok():
				return 'lightdm_account_service'

		return login_manager

	def kde_greeter_is_installed(self):
		return 0 == subprocess.call(
			['dpkg', '-s', 'lightdm-kde-greeter'],
			stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)

	def theme_with_accountsservice_is_ok(self):
		if os.path.isfile('/etc/lightdm/lightdm-kde-greeter.conf'):
			with open('/etc/lightdm/lightdm-kde-greeter.conf', 'r') as greeter_config_file:
				for line in greeter_config_file:
					if 'theme-name' in line:
						greeter = line.split('=', 1)[-1].strip()
						if greeter == 'classic':
							return True
		return False


class LoginManagerConfigurator(LoginManagerConfigurationChecker):
	def enable_login_with_foreign_usernames(self):
		# TODO: Kubuntu 16.04 uses sddm, which doesn't quite work so well unconfigured.
		# Need to check more distros for compatibility...
		if self.login_manager_compatible():
			self.enable_login_with_foreign_usernames_for_lightdm()

	def enable_login_with_foreign_usernames_for_lightdm(self):
		print('Writing /etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf ', end='... ')
		sys.stdout.flush()

		lightdm_config = \
			'[SeatDefaults]\n' \
			'greeter-show-manual-login=true\n' \
			'greeter-hide-users=true\n'

		if not os.path.exists('/etc/lightdm/lightdm.conf.d'):
			os.mkdir('/etc/lightdm/lightdm.conf.d')

		with open('/etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf', 'w') as conf_file:
			conf_file.write(lightdm_config)

		print('Done.')
