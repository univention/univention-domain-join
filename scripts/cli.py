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

import argparse
import importlib
import logging
import os
import subprocess
import sys
from getpass import getpass
from logging import getLogger
from typing import Dict

from univention_domain_join.distributions import AbstractJoiner
from univention_domain_join.utils.distributions import get_distribution
from univention_domain_join.utils.domain import get_master_ip_through_dns, get_ucs_domainname
from univention_domain_join.utils.general import execute_as_root

OUTPUT_SINK = open(os.devnull, 'w')


def check_if_run_as_root() -> None:
	if os.getuid() != 0:
		print('This tool must be executed as root.')
		exit(1)


@execute_as_root
def set_up_logging() -> None:
	verbose_formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
	plain_formatter = logging.Formatter('%(message)s')

	if not os.path.exists('/var/log/univention/'):
		os.makedirs('/var/log/univention/')
	logfile_handler = logging.FileHandler('/var/log/univention/domain-join-cli.log')
	logfile_handler.setLevel(logging.DEBUG)
	logfile_handler.setFormatter(verbose_formatter)

	stdout_handler = logging.StreamHandler(sys.stdout)
	stdout_handler.setLevel(logging.DEBUG)
	stdout_handler.setFormatter(plain_formatter)

	userinfo_logger = logging.getLogger('userinfo')
	userinfo_logger.setLevel(logging.DEBUG)
	userinfo_logger.addHandler(logfile_handler)
	userinfo_logger.addHandler(stdout_handler)

	debugging_logger = logging.getLogger('debugging')
	debugging_logger.setLevel(logging.DEBUG)
	debugging_logger.addHandler(logfile_handler)


def get_joiner_for_this_distribution(dc_ip: str, admin_username: str, admin_pw: str, skip_login_manager: bool, force_ucs_dns: bool) -> AbstractJoiner:
	distribution = get_distribution()
	try:
		distribution_join_module = importlib.import_module('univention_domain_join.distributions.%s' % (distribution.lower(),))
		if not admin_username:
			admin_username = get_admin_username()
		if not admin_pw:
			admin_pw = get_admin_password(admin_username)
		check_if_ssh_works_with_given_account(dc_ip, admin_username, admin_pw)
		ucr_variables = get_ucr_variables_from_dc(dc_ip, admin_username, admin_pw)
		return distribution_join_module.Joiner(ucr_variables, admin_username, admin_pw, dc_ip, skip_login_manager, force_ucs_dns)
	except ImportError:
		getLogger("userinfo").critical('The used distribution "%s" is not supported.' % (distribution,))
		exit(1)


def get_admin_username() -> str:
	return input('Please enter the user name of a domain administrator: ')


def get_admin_password(admin_username: str) -> str:
	# TODO: Don't ask for the password if ssh works passwordless already.
	return getpass(prompt='Please enter the password for %s: ' % (admin_username,))


@execute_as_root
def check_if_ssh_works_with_given_account(dc_ip: str, admin_username: str, admin_pw: str) -> None:
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (admin_username, dc_ip), 'echo foo'],
		stdin=subprocess.PIPE, stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
	)
	ssh_process.communicate(admin_pw.encode())
	if ssh_process.returncode != 0:
		getLogger("userinfo").critical('It\'s not possible to connect to the UCS DC via ssh, with the given credentials.')
		exit(1)


@execute_as_root
def get_ucr_variables_from_dc(dc_ip: str, admin_username: str, admin_pw: str) -> Dict[str, str]:
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (admin_username, dc_ip), '/usr/sbin/ucr shell | grep -v ^hostname='],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(admin_pw.encode())
	if ssh_process.returncode != 0:
		getLogger("userinfo").critical('Fetching the UCR variables from the UCS DC failed.')
		exit(1)
	ucr_variables = {}
	for raw_ucr_variable in stdout.splitlines():
		key, value = raw_ucr_variable.decode('utf-8', 'replace').strip().split('=', 1)
		ucr_variables[key] = value
	return ucr_variables


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description='Tool for joining a client computer into an UCS domain.'
	)
	parser.add_argument('--username', help='User name of a domain administrator')
	parser.add_argument('--password', help='Password for the domain administrator')
	parser.add_argument('--password-file', help='Path to a file, containing the password for the domain administrator', metavar="FILE")
	parser.add_argument('--skip-login-manager', action='store_true', help='Do not configure the login manager')
	parser.add_argument('--domain', help='Domain name. Can be left out if the domain is configured for this system')
	parser.add_argument('--dc-ip', help='IP address of the UCS domain controller to join to. Can be used if --domain does not work. If unsure, use the IP of the UCS Master', metavar="IP")
	parser.add_argument('--force-ucs-dns', action='store_true', help='Change the system\'s DNS settings and set the UCS DC as DNS nameserver (default is to use the standard network settings, but make sure the your system can resolve the hostname of the UCS DC and the UCS master system)')
	args = parser.parse_args()
	return args


if __name__ == '__main__':
	args = parse_args()

	check_if_run_as_root()
	sudo_uid = os.environ.get('SUDO_UID')
	if sudo_uid:
		os.seteuid(int(sudo_uid))

	set_up_logging()

	try:
		if not args.dc_ip:
			if not args.domain:
				args.domain = get_ucs_domainname()
				getLogger("userinfo").info('Automatically detected the domain %r.' % (args.domain))
			if not args.domain:
				getLogger("userinfo").critical(
					'Unable to determine the UCS domain automatically. Please provide '
					'it using the --domain parameter or use the tool with --dc-ip.'
				)
				exit(1)
			args.dc_ip = get_master_ip_through_dns(args.domain)
			if not args.dc_ip:
				getLogger("userinfo").critical(
					'No DNS record for the DC master could be found. Please make sure that '
					'the DC master is the DNS server for this computer or use this tool with --dc-ip.'
				)
				exit(1)

		if args.password:
			password = args.password
		elif args.password_file:
			try:
				with open(args.password_file) as password_file:
					password = password_file.read().strip()
			except IOError:
				getLogger("userinfo").error('Error: The password file could not be read.')
				password = None
		else:
			password = None

		distribution_joiner = get_joiner_for_this_distribution(args.dc_ip, args.username, password, args.skip_login_manager, args.force_ucs_dns)
		distribution_joiner.check_if_join_is_possible_without_problems()
		distribution_joiner.create_backup_of_config_files()
		distribution_joiner.join_domain()
	except Exception as e:
		getLogger("userinfo").critical('An error occurred: %s. Please check %s for more information.' % (e, debugging_logger.handlers[0].baseFilename,))
		getLogger("debugging").critical(e, exc_info=True)
		exit(1)
