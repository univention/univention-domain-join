from __future__ import print_function
import os
import paramiko
import pipes
import stat
import subprocess
import sys

from root_certificate_provider import RootCertificateProvider


class LdapConfigurationChecker(object):
	def ldap_configured(self, master_ip, master_pw, ldap_base):
		return (
			self.ldap_conf_exists() and
			self.machine_secret_exists() and
			self.machine_exists_in_ldap(master_ip, master_pw, ldap_base)
		)

	def ldap_conf_exists(self):
		return os.path.isfile('/etc/ldap/ldap.conf')

	def machine_secret_exists(self):
		return os.path.isfile('/etc/machine.secret')

	def machine_exists_in_ldap(self, master_ip, master_pw, ldap_base):
		udm_command = ['udm', 'computers/ubuntu', 'list', '--position', 'cn=%s,cn=computers,%s' % (self.hostname, ldap_base)]
		escaped_udm_command = ' '.join([pipes.quote(x) for x in udm_command])
		with paramiko.SSHClient() as ssh_client:
			ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh_client.connect(master_ip, username='root', password=master_pw)
			stdin, stdout, stderr = ssh_client.exec_command(escaped_udm_command)
			return stdout.channel.recv_exit_status() == 0


class LdapConfigurator(LdapConfigurationChecker):
	def __init__(self):
		self.hostname = subprocess.check_output(['hostname']).strip()

	def configure_ldap(self, master_ip, master_pw, ldap_master, ldap_base):
		RootCertificateProvider().provide_ucs_root_certififcate(ldap_master)
		password = self.random_password()
		self.delete_old_entry_and_add_machine_to_ldap(password, master_ip, master_pw, ldap_base)
		self.write_hosts_entry_for_master(master_ip, ldap_master)
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
		# TODO: Differentiate between computers/ubuntu and computers/linux.
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

	def write_hosts_entry_for_master(self, master_ip, ldap_master):
		self.remove_old_hosts_entry_if_exists(ldap_master)

		print('Adding entry for the master to /etc/hosts ', end='... ')
		sys.stdout.flush()

		with open('/etc/hosts', 'a') as hosts_file:
			hosts_file.write('%s %s\n' % (master_ip, ldap_master))

		print('Done.')

	def remove_old_hosts_entry_if_exists(self, name):
		old_entry_exists = False
		with open('/etc/hosts', 'r') as hosts_file:
			new_hosts = []
			for line in hosts_file:
				if name in line:
					old_entry_exists = True
				else:
					new_hosts.append(line)

		if old_entry_exists:
			print('Removing old entry for the master in /etc/hosts ', end='... ')
			sys.stdout.flush()

			with open('/etc/hosts', 'w') as hosts_file:
				for line in new_hosts:
					hosts_file.write(line)

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
