from __future__ import print_function
from shutil import copyfile
import os
import subprocess
import sys

OUTPUT_SINK = open(os.devnull, 'w')


class ConflictChecker(object):
	def configuration_conflicts(self):
		return self.config_file_exists()

	def config_file_exists(self):
		if os.path.isfile('/etc/krb5.conf'):
			print('Warning: /etc/krb5.conf already exists.')
			return True
		return False


class KerberosConfigurator(ConflictChecker):
	def backup(self, backup_dir):
		if self.config_file_exists():
			if not os.path.exists(os.path.join(backup_dir, 'etc')):
				os.makedirs(os.path.join(backup_dir, 'etc'))
			copyfile(
				'/etc/krb5.conf',
				os.path.join(backup_dir, 'etc/krb5.conf')
			)

	def configure_kerberos(self, kerberos_realm, master_ip, ldap_master):
		self.write_config_file(kerberos_realm, master_ip, ldap_master)
		self.synchronize_time_with_master(ldap_master)

	def write_config_file(self, kerberos_realm, master_ip, ldap_master):
		print('Writing /etc/krb5.conf ', end='... ')
		sys.stdout.flush()

		config = \
			'[libdefaults]\n' \
			'    default_realm = %(kerberos_realm)s\n' \
			'    kdc_timesync = 1\n' \
			'    ccache_type = 4\n' \
			'    forwardable = true\n' \
			'    proxiable = true\n' \
			'    default_tkt_enctypes = arcfour-hmac-md5 des-cbc-md5 des3-hmac-sha1 des-cbc-crc des-cbc-md4 des3-cbc-sha1 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96\n' \
			'    permitted_enctypes = des3-hmac-sha1 des-cbc-crc des-cbc-md4 des-cbc-md5 des3-cbc-sha1 arcfour-hmac-md5 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96\n' \
			'    allow_weak_crypto=true\n' \
			'\n' \
			'[realms]\n' \
			'%(kerberos_realm)s = {\n' \
			'   kdc = %(master_ip)s $(ldap_master)s\n' \
			'   admin_server = %(master_ip)s %(ldap_master)s\n' \
			'   kpasswd_server = %(master_ip) %(ldap_master)s\n' \
			'}\n' \
			% {
				'kerberos_realm': kerberos_realm,
				'master_ip': master_ip,
				'ldap_master': ldap_master
			}

		with open('/etc/krb5.conf', 'w') as conf_file:
			conf_file.write(config)

		print('Done.')

	def synchronize_time_with_master(self, ldap_master):
		print('Synchronizing time with the DC master', end='... ')
		sys.stdout.flush()

		subprocess.check_call(
			['ntpdate', '-bu', ldap_master],
			stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)

		print('Done.')
