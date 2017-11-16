from __future__ import print_function
import os
import subprocess
import sys

OUTPUT_SINK = open(os.devnull, 'w')


class PamConfigurationChecker(object):
	def pam_configured(self):
		return self.group_conf_file_exists() and self.home_dir_conf_file_exists()

	def home_dir_conf_file_exists(self):
		return os.path.isfile('/usr/share/pam-configs/ucs_mkhomedir')

	def group_conf_file_exists(self):
		return os.path.isfile('/usr/share/pam-configs/local_groups')


class PamConfigurator(PamConfigurationChecker):
	def setup_pam(self):
		self.configure_home_dir_creation()
		self.add_users_to_requiered_system_groups()
		self.update_pam()

	def configure_home_dir_creation(self):
		print('Writing /usr/share/pam-configs/ucs_mkhomedir ', end='... ')
		sys.stdout.flush()

		home_dir_conf = \
			'Name: activate mkhomedir\n' \
			'Default: yes\n' \
			'Priority: 900\n'\
			'Session-Type: Additional\n' \
			'Session:\n' \
			'    required    pam_mkhomedir.so umask=0022 skel=/etc/skel\n'
		with open('/usr/share/pam-configs/ucs_mkhomedir', 'w') as conf_file:
			conf_file.write(home_dir_conf)

		print('Done.')

	def add_users_to_requiered_system_groups(self):
		self.add_groups_to_group_conf()
		self.write_pam_group_conf()

	def add_groups_to_group_conf(self):
		if self.group_conf_already_ok():
			return

		print('Adding  groups to /etc/security/group.conf ', end='... ')
		sys.stdout.flush()

		# TODO: Research which groups would be adequate (on Ubuntu).
		with open('/etc/security/group.conf', 'a') as groups_file:
			groups_file.write(
				'*;*;*;Al0000-2400;audio,cdrom,dialout,floppy,plugdev,adm\n'
			)

		print('Done.')

	def group_conf_already_ok(self):
		with open('/etc/security/group.conf', 'r') as groups_file:
			for line in groups_file:
				if '*;*;*;Al0000-2400;audio,cdrom,dialout,floppy,plugdev,adm\n' in line:
					return True
		return False

	def write_pam_group_conf(self):
		print('Adding  groups to /usr/share/pam-configs/local_groups ', end='... ')
		sys.stdout.flush()

		group_conf = \
			'Name: activate /etc/security/group.conf\n' \
			'Default: yes\n' \
			'Priority: 900\n' \
			'Auth-Type: Primary\n' \
			'Auth:\n' \
			'	    required    pam_group.so use_first_pass\n'

		# TODO: Is overwriting OK here?
		with open('/usr/share/pam-configs/local_groups', 'w') as conf_file:
			conf_file.write(group_conf)

		print('Done.')

	def update_pam(self):
		print('Updating PAM', end='... ')
		sys.stdout.flush()

		env = os.environ.copy()
		env['DEBIAN_FRONTEND'] = 'noninteractive'
		subprocess.check_call(
			['pam-auth-update', '--force'],
			env=env, stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)

		print('Done.')
