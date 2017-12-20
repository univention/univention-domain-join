import logging
import os
import subprocess

OUTPUT_SINK = open(os.devnull, 'w')

userinfo_logger = logging.getLogger('userinfo')


class RootCertificateProvider(object):
	def provide_ucs_root_certififcate(self, ldap_master):
		if not self.ucs_root_certificate_available_localy():
			self.download_ucs_root_certificate(ldap_master)

	def download_ucs_root_certificate(self, ldap_master):
		userinfo_logger.info('Downloading the UCS root certificate to /etc/univention/ssl/ucsCA/CAcert.pem ')

		if not os.path.exists('/etc/univention/ssl/ucsCA'):
			os.makedirs('/etc/univention/ssl/ucsCA')
		subprocess.check_call(
			['wget', '-O', '/etc/univention/ssl/ucsCA/CAcert.pem', 'http://%s/ucs-root-ca.crt' % (ldap_master,)],
			stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)

	def ucs_root_certificate_available_localy(self):
		return os.path.isfile('/etc/univention/ssl/ucsCA/CAcert.pem')
