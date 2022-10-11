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
import subprocess
from functools import wraps
from pipes import quote
from typing import Any, Callable, List, TypeVar, Union, cast

F = TypeVar('F', bound=Callable[..., Any])


def execute_as_root(func: F) -> F:
	@wraps(func)
	def root_wrapper(*args: Any, **kwargs: Any) -> Any:
		old_euid = os.geteuid()
		os.seteuid(0)
		try:
			return_value = func(*args, **kwargs)
		finally:
			os.seteuid(old_euid)
		return return_value
	return cast(F, root_wrapper)


def name_is_resolvable(name: str) -> bool:
	try:
		return bool(socket.getaddrinfo(name, 22, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP))
	except Exception:
		return False


def ssh(username: str, password: str, hostname: str, command: Union[str, List[str]], **kwargs: Any) -> subprocess.Popen:
	cmd = [
		"sshpass",
		"-e",  # Password is passed as env-var "SSHPASS"
		"ssh",
		"-F", "none",
		# "-o", "BatchMode=yes",  # conflicts with `sshpass`
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-l", username,
		hostname,
		command if isinstance(command, str) else " ".join(quote(arg) for arg in command),
	]
	env = dict(kwargs.pop("env", os.environ), SSHPASS=password)
	proc = subprocess.Popen(cmd, env=env, **kwargs)
	return proc
