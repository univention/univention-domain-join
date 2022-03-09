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

import os
import socket


def execute_as_root(func):
	def root_wrapper(*args, **kwargs):
		old_euid = os.geteuid()
		os.seteuid(0)
		try:
			return_value = func(*args, **kwargs)
		finally:
			os.seteuid(old_euid)
		return return_value
	return root_wrapper


def name_is_resolvable(name):
	try:
		return bool(socket.getaddrinfo(name, 22, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP))
	except Exception:
		return False
