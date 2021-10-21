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

from shutil import copyfile
import logging
import os
import subprocess

from univention_domain_join.utils.general import execute_as_root

OUTPUT_SINK = open(os.devnull, 'w')

userinfo_logger = logging.getLogger('userinfo')


class ConflictChecker(object):
	def configuration_conflicts(self):
		login_manager = self.determin_used_login_manager()
		if login_manager in ['lightdm', 'gdm3', 'sddm']:
			return False
		elif login_manager == 'lightdm_account_service':
			userinfo_logger.error('Error: The login won\'t work with your system, because you are using an incompatible login theme.')
			userinfo_logger.error('       Please go to "System Settings" -> "Login Screen (LightDM)" and set your login theme to "Classic".')
		else:
			userinfo_logger.error('Error: Can\'t enable login with the login manager of your system.')
			userinfo_logger.error('       Please use LightDM, SDDM or GDM for full compatibility with UCS.')
			userinfo_logger.error('       This error can be avoided by using the --skip-login-manager parameter.')
		return True

	def determin_used_login_manager(self):
		with open('/etc/X11/default-display-manager', 'r') as login_manager_file:
			login_manager = os.path.basename(login_manager_file.read()).strip()

		# The lightdm config files will be ignored with a certain setup (e.g. in
		# Kubuntu 14.04), so check for that.
		if login_manager == 'lightdm' and self.kde_greeter_is_installed():
			if not self.theme_with_accountsservice_is_ok():
				return 'lightdm_account_service'

		return login_manager

	def lightdm_config_file_exists(self):
		if os.path.isfile('/etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf'):
			userinfo_logger.warn('Warning: /etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf already exists.')
			return True
		return False

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


class LoginManagerConfigurator(ConflictChecker):

	@execute_as_root
	def backup(self, backup_dir):
		if self.lightdm_config_file_exists():
			os.makedirs(os.path.join(backup_dir, 'etc/lightdm/lightdm.conf.d'))
			copyfile(
				'/etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf',
				os.path.join(backup_dir, 'etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf')
			)

	def enable_login_with_foreign_usernames(self):
		login_manager = self.determin_used_login_manager()
		if login_manager == 'lightdm':
			self.enable_login_with_foreign_usernames_for_lightdm()

	@execute_as_root
	def enable_login_with_foreign_usernames_for_lightdm(self):
		userinfo_logger.info('Writing /etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf ')

		lightdm_config = \
			'[SeatDefaults]\n' \
			'greeter-show-manual-login=true\n' \
			'greeter-hide-users=true\n'

		if not os.path.exists('/etc/lightdm/lightdm.conf.d'):
			os.mkdir('/etc/lightdm/lightdm.conf.d')

		with open('/etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf', 'w') as conf_file:
			conf_file.write(lightdm_config)
