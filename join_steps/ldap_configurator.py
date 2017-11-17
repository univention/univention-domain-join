from __future__ import print_function
import os
import paramiko
import pipes
import stat
import subprocess
import sys

from root_certificate_provider import RootCertificateProvider


class ConflictChecker(object):
	def configuration_conflicts(self):
		# self.machine_exists_in_ldap() is not considered a problem here.
		return self.ldap_conf_exists()

	def ldap_conf_exists(self):
		if os.path.isfile('/etc/ldap/ldap.conf'):
			print('Warning: /etc/ldap/ldap.conf already exists.')
			return True
		return False

	def machine_exists_in_ldap(self, master_ip, master_pw, ldap_base):
		udm_command = ['udm', 'computers/ubuntu', 'list', '--position', 'cn=%s,cn=computers,%s' % (self.hostname, ldap_base)]
		escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
		with paramiko.SSHClient() as ssh_client:
			ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh_client.connect(master_ip, username='root', password=master_pw)
			stdin, stdout, stderr = ssh_client.exec_command(escaped_udm_command)
			return stdout.channel.recv_exit_status() == 0


class LdapConfigurator(ConflictChecker):
	def __init__(self):
		self.hostname = subprocess.check_output(['hostname']).strip()

	def configure_ldap(self, master_ip, master_pw, ldap_master, ldap_base):
		RootCertificateProvider().provide_ucs_root_certififcate(ldap_master)
		password = self.random_password()
		self.delete_old_entry_and_add_machine_to_ldap(password, master_ip, master_pw, ldap_base)
		self.create_ldap_conf_file(ldap_master, ldap_base)
		self.create_machine_secret_file(password)

	def delete_old_entry_and_add_machine_to_ldap(self, password, master_ip, master_pw, ldap_base):
		if self.machine_exists_in_ldap(master_ip, master_pw, ldap_base):
			self.delete_machine_from_ldap(master_ip, master_pw, ldap_base)
		self.add_machine_to_ldap(password, master_ip, master_pw, ldap_base)

	def delete_machine_from_ldap(self, master_ip, master_pw, ldap_base):
		print('Removing old LDAP entry for this machine on the DC master', end='... ')
		sys.stdout.flush()

		udm_command = ['udm', 'computers/ubuntu', 'remove', '--dn', 'cn=%s,cn=computers,%s' % (self.hostname, ldap_base)]
		escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
		with paramiko.SSHClient() as ssh_client:
			ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh_client.connect(master_ip, username='root', password=master_pw)
			stdin, stdout, stderr = ssh_client.exec_command(escaped_udm_command)
			if stdout.channel.recv_exit_status() != 0:
				raise Exception('Removing the old LDAP entry for this computer failed.')

		print('Done.')

	def add_machine_to_ldap(self, password, master_ip, master_pw, ldap_base):
		print('Adding LDAP entry for this machine on the DC master', end='... ')
		sys.stdout.flush()

		release_id = subprocess.check_output(['lsb_release', '-is'])
		release = subprocess.check_output(['lsb_release', '-rs'])

		# TODO: Also add MAC address.
		udm_command = [
			'udm', 'computers/ubuntu', 'create',
			'--position', 'cn=computers,%s' % (ldap_base,),
			'--set', 'name=%s' % (self.hostname,),
			'--set', 'password=%s' % (password,),
			'--set', 'operatingSystem=%s' % (release_id,),
			'--set', 'operatingSystemVersion=%s' % (release,)
		]
		escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
		with paramiko.SSHClient() as ssh_client:
			ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh_client.connect(master_ip, username='root', password=master_pw)
			stdin, stdout, stderr = ssh_client.exec_command(escaped_udm_command)
			if stdout.channel.recv_exit_status() != 0:
				raise Exception('Adding a LDAP object for this computer didn\'t work.')

		print('Done.')

	def create_ldap_conf_file(self, ldap_master, ldap_base):
		print('Writing /etc/ldap/ldap.conf ', end='... ')
		sys.stdout.flush()

		ldap_conf = \
			"TLS_CACERT /etc/univention/ssl/ucsCA/CAcert.pem\n" \
			"URI ldap://%s:7389\n" \
			"BASE %s\n" \
			% (ldap_master, ldap_base)

		with open('/etc/ldap/ldap.conf', 'w') as conf_file:
			conf_file.write(ldap_conf)

		print('Done.')

	def create_machine_secret_file(self, password):
		print('Writing /etc/machine.secret ', end='... ')
		sys.stdout.flush()

		with open('/etc/machine.secret', 'w') as secret_file:
			secret_file.write(password)
		os.chmod('/etc/machine.secret', stat.S_IREAD)

		print('Done.')

	def random_password(self, length=20):
		chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[]^_`{|}~'
		password = ''
		for _ in range(length):
			password += chars[ord(os.urandom(1)) % len(chars)]
		return password
