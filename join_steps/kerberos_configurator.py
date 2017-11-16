from __future__ import print_function
import os
import subprocess
import sys

OUTPUT_SINK = open(os.devnull, 'w')


class KerberosConfigurationChecker(object):
	def kerberos_configured(self, ldap_master):
		return self.config_file_contains_master(ldap_master)

	def config_file_contains_master(self, ldap_master):
		if os.path.isfile('/etc/krb5.conf'):
			with open('/etc/krb5.conf', 'r') as conf_file:
				for line in conf_file:
					if ldap_master in line:
						return True
		return False


class KerberosConfigurator(KerberosConfigurationChecker):
	def configure_kerberos(self, kerberos_realm, master_ip, ldap_master):
		# TODO: No TGT is requested here. Wouldn't that be easier for the user?
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
