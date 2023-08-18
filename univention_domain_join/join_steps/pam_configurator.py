#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

import logging
import os
import subprocess
from shutil import copyfile

from univention_domain_join.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')


class ConflictChecker(object):
	def home_dir_conf_file_exists(self) -> bool:
		if os.path.isfile('/usr/share/pam-configs/ucs_mkhomedir'):
			userinfo_logger.warn('Warning: /usr/share/pam-configs/ucs_mkhomedir already exists.')
			return True
		return False

	def group_conf_file_exists(self) -> bool:
		if os.path.isfile('/usr/share/pam-configs/local_groups'):
			userinfo_logger.warn('Warning: /usr/share/pam-configs/local_groups already exists.')
			return True
		return False


class PamConfigurator(ConflictChecker):

	@execute_as_root
	def backup(self, backup_dir: str) -> None:
		copy_home_dir_conf = self.home_dir_conf_file_exists()
		copy_group_conf = self.group_conf_file_exists()
		if copy_home_dir_conf or copy_group_conf:
			os.makedirs(os.path.join(backup_dir, 'usr/share/pam-configs'), exist_ok=True)
		if copy_home_dir_conf:
			copyfile(
				'/usr/share/pam-configs/ucs_mkhomedir',
				os.path.join(backup_dir, 'usr/share/pam-configs/ucs_mkhomedir')
			)
		if copy_group_conf:
			copyfile(
				'/usr/share/pam-configs/local_groups',
				os.path.join(backup_dir, 'usr/share/pam-configs/local_groups')
			)
		os.makedirs(os.path.join(backup_dir, 'etc/security'), exist_ok=True)
		copyfile(
			'/etc/security/group.conf',
			os.path.join(backup_dir, 'etc/security/group.conf')
		)

	def setup_pam(self) -> None:
		self.configure_home_dir_creation()
		self.add_users_to_requiered_system_groups()
		self.update_pam()

	@execute_as_root
	def configure_home_dir_creation(self) -> None:
		userinfo_logger.info('Writing /usr/share/pam-configs/ucs_mkhomedir ')

		home_dir_conf = \
			'Name: activate mkhomedir\n' \
			'Default: yes\n' \
			'Priority: 900\n'\
			'Session-Type: Additional\n' \
			'Session:\n' \
			'    required    pam_mkhomedir.so umask=0022 skel=/etc/skel\n'
		with open('/usr/share/pam-configs/ucs_mkhomedir', 'w') as conf_file:
			conf_file.write(home_dir_conf)

	def add_users_to_requiered_system_groups(self) -> None:
		self.add_groups_to_group_conf()
		self.write_pam_group_conf()

	@execute_as_root
	def add_groups_to_group_conf(self) -> None:
		if self.group_conf_already_ok():
			return

		userinfo_logger.info('Adding  groups to /etc/security/group.conf ')

		# TODO: Would additional groups be appropriate here?
		with open('/etc/security/group.conf', 'a') as groups_file:
			groups_file.write(
				'*;*;*;Al0000-2400;audio,cdrom,dialout,floppy,plugdev,adm\n'
			)

	def group_conf_already_ok(self) -> bool:
		with open('/etc/security/group.conf', 'r') as groups_file:
			for line in groups_file:
				if '*;*;*;Al0000-2400;audio,cdrom,dialout,floppy,plugdev,adm\n' in line:
					return True
		return False

	@execute_as_root
	def write_pam_group_conf(self) -> None:
		userinfo_logger.info('Adding  groups to /usr/share/pam-configs/local_groups ')

		group_conf = \
			'Name: activate /etc/security/group.conf\n' \
			'Default: yes\n' \
			'Priority: 900\n' \
			'Auth-Type: Primary\n' \
			'Auth:\n' \
			'	    required    pam_group.so use_first_pass\n'

		with open('/usr/share/pam-configs/local_groups', 'w') as conf_file:
			conf_file.write(group_conf)

	@execute_as_root
	def update_pam(self) -> None:
		userinfo_logger.info('Updating PAM')

		env = os.environ.copy()
		env['DEBIAN_FRONTEND'] = 'noninteractive'
		subprocess.check_output(
			['pam-auth-update', '--force'],
			env=env, stderr=subprocess.STDOUT
		)
