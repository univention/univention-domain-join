from shutil import copyfile
import logging
import os
import pipes
import stat
import subprocess

from root_certificate_provider import RootCertificateProvider

userinfo_logger = logging.getLogger('userinfo')

OUTPUT_SINK = open(os.devnull, 'w')


class ConflictChecker(object):
	def ldap_conf_exists(self):
		if os.path.isfile('/etc/ldap/ldap.conf'):
			userinfo_logger.warn('Warning: /etc/ldap/ldap.conf already exists.')
			return True
		return False

	def machine_exists_in_ldap(self, ldap_master, master_username, master_pw, ldap_base):
		udm_command = ['/usr/sbin/udm', 'computers/ubuntu', 'list', '--position', 'cn=%s,cn=computers,%s' % (self.hostname, ldap_base)]
		escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
		ssh_process = subprocess.Popen(
			['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_master), escaped_udm_command],
			stdin=subprocess.PIPE, stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)
		ssh_process.communicate(master_pw)
		machine_exists = ssh_process.returncode == 0
		return machine_exists


class LdapConfigurator(ConflictChecker):
	def __init__(self):
		self.hostname = subprocess.check_output(['hostname', '-s']).strip()

	def backup(self, backup_dir):
		if self.ldap_conf_exists():
			os.makedirs(os.path.join(backup_dir, 'etc/ldap'))
			copyfile(
				'/etc/ldap/ldap.conf',
				os.path.join(backup_dir, 'etc/ldap/ldap.conf')
			)

	def configure_ldap(self, ldap_master, master_username, master_pw, ldap_base):
		RootCertificateProvider().provide_ucs_root_certififcate(ldap_master)
		password = self.random_password()
		self.delete_old_entry_and_add_machine_to_ldap(password, ldap_master, master_username, master_pw, ldap_base)
		self.create_ldap_conf_file(ldap_master, ldap_base)
		self.create_machine_secret_file(password)

	def delete_old_entry_and_add_machine_to_ldap(self, password, ldap_master, master_username, master_pw, ldap_base):
		if self.machine_exists_in_ldap(ldap_master, master_username, master_pw, ldap_base):
			self.delete_machine_from_ldap(ldap_master, master_username, master_pw, ldap_base)
		self.add_machine_to_ldap(password, ldap_master, master_username, master_pw, ldap_base)

	def delete_machine_from_ldap(self, ldap_master, master_username, master_pw, ldap_base):
		userinfo_logger.info('Removing old LDAP entry for this machine on the DC master')

		udm_command = ['/usr/sbin/udm', 'computers/ubuntu', 'remove', '--dn', 'cn=%s,cn=computers,%s' % (self.hostname, ldap_base)]
		escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
		ssh_process = subprocess.Popen(
			['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_master), escaped_udm_command],
			stdin=subprocess.PIPE, stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)
		ssh_process.communicate(master_pw)
		if ssh_process.returncode != 0:
			userinfo_logger.critical('Removing the old LDAP entry for this computer failed.')
			exit(1)

	def add_machine_to_ldap(self, password, ldap_master, master_username, master_pw, ldap_base):
		userinfo_logger.info('Adding LDAP entry for this machine on the DC master')

		release_id = subprocess.check_output(['lsb_release', '-is'])
		release = subprocess.check_output(['lsb_release', '-rs'])

		# TODO: Also add MAC address. Which NIC's address should I use?
		udm_command = [
			'/usr/sbin/udm', 'computers/ubuntu', 'create',
			'--position', 'cn=computers,%s' % (ldap_base,),
			'--set', 'name=%s' % (self.hostname,),
			'--set', 'password=%s' % (password,),
			'--set', 'operatingSystem=%s' % (release_id,),
			'--set', 'operatingSystemVersion=%s' % (release,)
		]
		escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
		ssh_process = subprocess.Popen(
			['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, ldap_master), escaped_udm_command],
			stdin=subprocess.PIPE, stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)
		ssh_process.communicate(master_pw)
		if ssh_process.returncode != 0:
			userinfo_logger.critical('Adding an LDAP object for this computer didn\'t work.')
			exit(1)

	def create_ldap_conf_file(self, ldap_master, ldap_base):
		userinfo_logger.info('Writing /etc/ldap/ldap.conf ')

		ldap_conf = \
			"TLS_CACERT /etc/univention/ssl/ucsCA/CAcert.pem\n" \
			"URI ldap://%s:7389\n" \
			"BASE %s\n" \
			% (ldap_master, ldap_base)

		with open('/etc/ldap/ldap.conf', 'w') as conf_file:
			conf_file.write(ldap_conf)

	def create_machine_secret_file(self, password):
		userinfo_logger.info('Writing /etc/machine.secret ')

		with open('/etc/machine.secret', 'w') as secret_file:
			secret_file.write(password)
		os.chmod('/etc/machine.secret', stat.S_IREAD)

	def random_password(self, length=20):
		chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[]^_`{|}~'
		password = ''
		for _ in range(length):
			password += chars[ord(os.urandom(1)) % len(chars)]
		return password
