from __future__ import print_function
import os
import subprocess
import sys

OUTPUT_SINK = open(os.devnull, 'w')


class RootCertificateProvider(object):
	def provide_ucs_root_certififcate(self, ldap_master):
		if not self.ucs_root_certificate_available_localy():
			self.download_ucs_root_certificate(ldap_master)

	def download_ucs_root_certificate(self, ldap_master):
		print('Downloading the UCS root certificate to /etc/univention/ssl/ucsCA/CAcert.pem ', end='... ')
		sys.stdout.flush()

		if not os.path.exists('/etc/univention/ssl/ucsCA'):
			os.makedirs('/etc/univention/ssl/ucsCA')
		subprocess.check_call(
			['wget', '-O', '/etc/univention/ssl/ucsCA/CAcert.pem', 'http://%s/ucs-root-ca.crt' % (ldap_master,)],
			stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)

		print('Done.')

	def ucs_root_certificate_available_localy(self):
		return os.path.isfile('/etc/univention/ssl/ucsCA/CAcert.pem')
