#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

import logging
import os
import subprocess

from univention_domain_join.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')


class RootCertificateProvider(object):
	def provide_ucs_root_certififcate(self, dc_ip: str) -> None:
		if not self.ucs_root_certificate_available_locally():
			self.download_ucs_root_certificate(dc_ip)
			self.add_certificate_to_certificate_store()

	def ucs_root_certificate_available_locally(self) -> bool:
		return os.path.isfile('/etc/univention/ssl/ucsCA/CAcert.pem') and \
			os.path.isfile('/usr/local/share/ca-certificates/UCSdomain.crt')

	@execute_as_root
	def download_ucs_root_certificate(self, dc_ip: str) -> None:
		userinfo_logger.info('Downloading the UCS root certificate to /etc/univention/ssl/ucsCA/CAcert.pem')

		os.makedirs('/etc/univention/ssl/ucsCA', exist_ok=True)
		subprocess.check_output(
			[
				'wget',
				'--no-check-certificate',
				'-O', '/etc/univention/ssl/ucsCA/CAcert.pem',
				'http://%s/ucs-root-ca.crt' % (dc_ip,)
			],
			stderr=subprocess.STDOUT
		)

	@execute_as_root
	def add_certificate_to_certificate_store(self) -> None:
		userinfo_logger.info('Adding the UCS root certificate to the certificate store')

		os.symlink('/etc/univention/ssl/ucsCA/CAcert.pem', '/usr/local/share/ca-certificates/UCSdomain.crt')
		subprocess.check_output(
			['update-ca-certificates'],
			stderr=subprocess.STDOUT
		)
