from shutil import copyfile
import logging
import os
import subprocess

OUTPUT_SINK = open(os.devnull, 'w')

userinfo_logger = logging.getLogger('userinfo')


class ConflictChecker(object):
	def home_dir_conf_file_exists(self):
		if os.path.isfile('/usr/share/pam-configs/ucs_mkhomedir'):
			userinfo_logger.warn('Warning: /usr/share/pam-configs/ucs_mkhomedir already exists.')
			return True
		return False

	def group_conf_file_exists(self):
		if os.path.isfile('/usr/share/pam-configs/local_groups'):
			userinfo_logger.warn('Warning: /usr/share/pam-configs/local_groups already exists.')
			return True
		return False


class PamConfigurator(ConflictChecker):

	def backup(self, backup_dir):
		copy_home_dir_conf = self.home_dir_conf_file_exists()
		copy_group_conf = self.group_conf_file_exists()
		if copy_home_dir_conf or copy_group_conf:
			os.makedirs(os.path.join(backup_dir, 'usr/share/pam-configs'))
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
		os.makedirs(os.path.join(backup_dir, 'etc/security'))
		copyfile(
			'/etc/security/group.conf',
			os.path.join(backup_dir, 'etc/security/group.conf')
		)

	def setup_pam(self):
		self.configure_home_dir_creation()
		self.add_users_to_requiered_system_groups()
		self.update_pam()

	def configure_home_dir_creation(self):
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

	def add_users_to_requiered_system_groups(self):
		self.add_groups_to_group_conf()
		self.write_pam_group_conf()

	def add_groups_to_group_conf(self):
		if self.group_conf_already_ok():
			return

		userinfo_logger.info('Adding  groups to /etc/security/group.conf ')

		# TODO: Would additional groups be appropriate here?
		with open('/etc/security/group.conf', 'a') as groups_file:
			groups_file.write(
				'*;*;*;Al0000-2400;audio,cdrom,dialout,floppy,plugdev,adm\n'
			)

	def group_conf_already_ok(self):
		with open('/etc/security/group.conf', 'r') as groups_file:
			for line in groups_file:
				if '*;*;*;Al0000-2400;audio,cdrom,dialout,floppy,plugdev,adm\n' in line:
					return True
		return False

	def write_pam_group_conf(self):
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

	def update_pam(self):
		userinfo_logger.info('Updating PAM')

		env = os.environ.copy()
		env['DEBIAN_FRONTEND'] = 'noninteractive'
		subprocess.check_call(
			['pam-auth-update', '--force'],
			env=env, stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)
