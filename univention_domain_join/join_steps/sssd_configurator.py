from shutil import copyfile
import logging
import os
import stat
import subprocess

from univention_domain_join.utils.general import execute_as_root
from univention_domain_join.join_steps.root_certificate_provider import RootCertificateProvider

OUTPUT_SINK = open(os.devnull, 'w')

userinfo_logger = logging.getLogger('userinfo')


class ConflictChecker(object):
	def sssd_conf_file_exists(self):
		if os.path.isfile('/etc/sssd/sssd.conf'):
			userinfo_logger.warn('Warning: /etc/sssd/sssd.conf already exists.')
			return True
		return False

	def sssd_profile_file_exists(self):
		if os.path.isfile('/etc/auth-client-config/profile.d/sss'):
			userinfo_logger.warn('Warning: /etc/auth-client-config/profile.d/sss already exists.')
			return True
		return False


class SssdConfigurator(ConflictChecker):

	@execute_as_root
	def backup(self, backup_dir):
		if self.sssd_conf_file_exists():
			os.makedirs(os.path.join(backup_dir, 'etc/sssd'))
			copyfile(
				'/etc/sssd/sssd.conf',
				os.path.join(backup_dir, 'etc/sssd/sssd.conf')
			)
		if self.sssd_profile_file_exists():
			os.makedirs(os.path.join(backup_dir, 'etc/auth-client-config/profile.d'))
			copyfile(
				'//etc/auth-client-config/profile.d/sss',
				os.path.join(backup_dir, 'etc/auth-client-config/profile.d/sss')
			)

	@execute_as_root
	def setup_sssd(self, master_ip, ldap_master, ldap_base, kerberos_realm):
		self.hostname = subprocess.check_output(['hostname', '-s']).strip()
		self.ldap_password = subprocess.check_output(['cat', '/etc/machine.secret']).strip()
		RootCertificateProvider().provide_ucs_root_certififcate(ldap_master)

		self.write_sssd_conf(master_ip, ldap_master, ldap_base, kerberos_realm)
		self.write_sssd_profile()
		self.configure_sssd()
		self.restart_sssd()

	@execute_as_root
	def write_sssd_conf(self, master_ip, ldap_master, ldap_base, kerberos_realm):
		userinfo_logger.info('Writing /etc/sssd/sssd.conf ')

		sssd_conf = \
			'[sssd]\n' \
			'config_file_version = 2\n' \
			'reconnection_retries = 3\n' \
			'sbus_timeout = 30\n' \
			'services = nss, pam, sudo\n' \
			'domains = %(kerberos_realm)s\n' \
			'\n' \
			'[nss]\n' \
			'reconnection_retries = 3\n' \
			'\n' \
			'[pam]\n' \
			'reconnection_retries = 3\n' \
			'\n' \
			'[domain/%(kerberos_realm)s]\n' \
			'auth_provider = krb5\n' \
			'krb5_kdcip = %(master_ip)s\n' \
			'krb5_realm = %(kerberos_realm)s\n' \
			'krb5_server = %(ldap_master)s\n' \
			'krb5_kpasswd = %(ldap_master)s\n' \
			'id_provider = ldap\n' \
			'ldap_uri = ldap://%(ldap_master)s:7389\n' \
			'ldap_search_base = %(ldap_base)s\n' \
			'ldap_tls_reqcert = never\n' \
			'ldap_tls_cacert = /etc/univention/ssl/ucsCA/CAcert.pem\n' \
			'cache_credentials = true\n' \
			'enumerate = true\n' \
			'ldap_default_bind_dn = cn=%(hostname)s,cn=computers,%(ldap_base)s\n' \
			'ldap_default_authtok_type = password\n' \
			'ldap_default_authtok = %(ldap_password)s\n' \
			% {
				'master_ip': master_ip,
				'kerberos_realm': kerberos_realm,
				'ldap_master': ldap_master,
				'ldap_base': ldap_base,
				'hostname': self.hostname,
				'ldap_password': self.ldap_password
			}
		with open('/etc/sssd/sssd.conf', 'w') as conf_file:
			conf_file.write(sssd_conf)
		os.chmod('/etc/sssd/sssd.conf', stat.S_IREAD | stat.S_IWRITE)

	@execute_as_root
	def write_sssd_profile(self):
		userinfo_logger.info('Writing /etc/auth-client-config/profile.d/sss ')

		sssd_profile = \
			'[sss]\n' \
			'nss_passwd=   passwd:   compat sss\n' \
			'nss_group=    group:    compat sss\n' \
			'nss_shadow=   shadow:   compat\n' \
			'nss_netgroup= netgroup: nis\n' \
			'\n' \
			'pam_auth=\n' \
			'        auth [success=3 default=ignore] pam_unix.so nullok_secure try_first_pass\n' \
			'        auth requisite pam_succeed_if.so uid >= 500 quiet\n' \
			'        auth [success=1 default=ignore] pam_sss.so use_first_pass\n' \
			'        auth requisite pam_deny.so\n' \
			'        auth required pam_permit.so\n' \
			'\n' \
			'pam_account=\n' \
			'        account required pam_unix.so\n' \
			'        account sufficient pam_localuser.so\n' \
			'        account sufficient pam_succeed_if.so uid < 500 quiet\n' \
			'        account [default=bad success=ok user_unknown=ignore] pam_sss.so\n' \
			'        account required pam_permit.so\n' \
			'\n' \
			'pam_password=\n' \
			'        password requisite pam_pwquality.so retry=3\n' \
			'        password sufficient pam_unix.so obscure sha512\n' \
			'        password sufficient pam_sss.so use_authtok\n' \
			'        password required pam_deny.so\n' \
			'\n' \
			'pam_session=\n' \
			'        session required pam_mkhomedir.so skel=/etc/skel/ umask=0077\n' \
			'        session optional pam_keyinit.so revoke\n' \
			'        session required pam_limits.so\n' \
			'        session [success=1 default=ignore] pam_sss.so\n' \
			'        session required pam_unix.so\n'
		with open('/etc/auth-client-config/profile.d/sss', 'w') as profile_file:
			profile_file.write(sssd_profile)

	@execute_as_root
	def configure_sssd(self):
		userinfo_logger.info('Configuring auth config profile for sssd')

		subprocess.check_call(
			['auth-client-config', '-a', '-p', 'sss'],
			stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)

	@execute_as_root
	def restart_sssd(self):
		userinfo_logger.info('Restarting sssd')

		subprocess.check_call(
			['service', 'sssd', 'restart'],
			stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)
