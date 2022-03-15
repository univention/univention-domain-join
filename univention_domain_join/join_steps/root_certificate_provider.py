#!/usr/bin/env python3
#
# Univention Domain Join
#
# Copyright 2017-2022 Univention GmbH
#
# http://www.univention.de/
#
# All rights reserved.
#
# The source code of this program is made available
# under the terms of the GNU Affero General Public License version 3
# (GNU AGPL V3) as published by the Free Software Foundation.
#
# Binary versions of this program provided by Univention to you as
# well as other copyrighted, protected or trademarked materials like
# Logos, graphics, fonts, specific documentations and configurations,
# cryptographic keys etc. are subject to a license agreement between
# you and Univention and not subject to the GNU AGPL V3.
#
# In the case you use this program under the terms of the GNU AGPL V3,
# the program is provided in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License with the Debian GNU/Linux or Univention distribution in file
# /usr/share/common-licenses/AGPL-3; if not, see
# <http://www.gnu.org/licenses/>.

import logging
import os
import subprocess

from univention_domain_join.utils.general import execute_as_root

OUTPUT_SINK = open(os.devnull, 'w')

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
		subprocess.check_call(
			[
				'wget',
				'--no-check-certificate',
				'-O', '/etc/univention/ssl/ucsCA/CAcert.pem',
				'http://%s/ucs-root-ca.crt' % (dc_ip,)
			],
			stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)

	@execute_as_root
	def add_certificate_to_certificate_store(self) -> None:
		userinfo_logger.info('Adding the UCS root certificate to the certificate store')

		os.symlink('/etc/univention/ssl/ucsCA/CAcert.pem', '/usr/local/share/ca-certificates/UCSdomain.crt')
		subprocess.call(
			['update-ca-certificates'],
			stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)
