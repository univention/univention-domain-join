#!/usr/bin/env python3
#
# Univention Domain Join
#
# Copyright 2017-2018 Univention GmbH
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

from getpass import getpass
import argparse
import importlib
import logging
import os
import subprocess
import sys

from univention_domain_join.utils.distributions import get_distribution
from univention_domain_join.utils.domain import get_master_ip_through_dns
from univention_domain_join.utils.domain import get_ucs_domainname
from univention_domain_join.utils.general import execute_as_root

OUTPUT_SINK = open(os.devnull, 'w')


def check_if_run_as_root():
	if os.getuid() != 0:
		print('This tool must be executed as root.')
		exit(1)


@execute_as_root
def set_up_logging():
	global userinfo_logger
	global debugging_logger

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


def get_joiner_for_this_distribution(master_ip, master_username, master_pw, skip_login_manager):
	distribution = get_distribution()
	try:
		distribution_join_module = importlib.import_module('univention_domain_join.distributions.%s' % (distribution.lower(),))
		if not master_username:
			master_username = get_masters_admin_username()
		if not master_pw:
			master_pw = get_masters_admin_password(master_username)
		check_if_ssh_works_with_given_account(master_ip, master_username, master_pw)
		masters_ucr_variables = get_ucr_variables_from_master(master_ip, master_username, master_pw)
		return distribution_join_module.Joiner(masters_ucr_variables, master_ip, master_username, master_pw, skip_login_manager)
	except ImportError:
		userinfo_logger.critical('The used distribution "%s" is not supported.' % (distribution,))
		exit(1)


def get_masters_admin_username():
	return raw_input('Please enter the user name of a domain administrator: ')


def get_masters_admin_password(master_username):
	# TODO: Don't ask for the password if ssh works passwordless already.
	return getpass(prompt='Please enter the password for %s: ' % (master_username,))


@execute_as_root
def check_if_ssh_works_with_given_account(master_ip, master_username, master_pw):
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, master_ip), 'echo foo'],
		stdin=subprocess.PIPE, stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
	)
	ssh_process.communicate(master_pw)
	if ssh_process.returncode != 0:
		userinfo_logger.critical('It\'s not possible to connect to the DC master via ssh, with the given credentials.')
		exit(1)


@execute_as_root
def get_ucr_variables_from_master(master_ip, master_username, master_pw):
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', '%s@%s' % (master_username, master_ip), '/usr/sbin/ucr shell | grep -v ^hostname='],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(master_pw)
	if ssh_process.returncode != 0:
		userinfo_logger.critical('Fetching the UCR variables from the master failed.')
		exit(1)
	ucr_variables = {}
	for raw_ucr_variable in stdout.splitlines():
		key, value = raw_ucr_variable.strip().split('=', 1)
		ucr_variables[key] = value
	return ucr_variables

if __name__ == '__main__':
	check_if_run_as_root()
	sudo_uid = os.environ.get('SUDO_UID')
	if sudo_uid:
		os.seteuid(int(sudo_uid))

	set_up_logging()

	try:
		parser = argparse.ArgumentParser(
			description='Tool for joining a client computer into an UCS domain.'
		)
		parser.add_argument('--username', help='User name of a domain administrator.')
		parser.add_argument('--password', help='Password for the domain administrator.')
		parser.add_argument('--password-file', help='Path to a file, containing the password for the domain administrator.')
		parser.add_argument('--skip-login-manager', action='store_true', help='Do not configure the login manager.')
		parser.add_argument('--domain', help='Domain name. Can be left out if the domain is configured for this system.')
		parser.add_argument('--master-ip', help='IP address of the domain controller master. Can be used if --domain does not work.')
		args = parser.parse_args()

		if args.master_ip:
			master_ip = args.master_ip
		else:
			if args.domain:
				domain = args.domain
			else:
				domain = get_ucs_domainname()
			if domain:
				userinfo_logger.info('Automatically detected the domain %r.' % (domain,))
			else:
				userinfo_logger.critical(
					'Unable to determine the UCS domain automatically. Please provide '
					'it using the --domain parameter or use the tool with --master-ip.'
				)
				exit(1)

			master_ip = get_master_ip_through_dns(domain)
			if not master_ip:
				userinfo_logger.critical(
					'No DNS record for the DC master could be found. Please make sure that '
					'the DC master is the DNS server for this computer or use this tool with --master-ip.'
				)
				exit(1)

		if args.password:
			password = args.password
		elif args.password_file:
			try:
				with open(args.password_file) as password_file:
					password = password_file.read().strip()
			except IOError:
				userinfo_logger.error('Error: The password file could not be read.')
				password = None
		else:
			password = None

		distribution_joiner = get_joiner_for_this_distribution(master_ip, args.username, password, args.skip_login_manager)

		distribution_joiner.check_if_join_is_possible_without_problems()
		distribution_joiner.create_backup_of_config_files()
		distribution_joiner.join_domain()
	except Exception as e:
		userinfo_logger.critical('An error occurred. Please check %s for more information.' % (debugging_logger.handlers[0].baseFilename,))
		debugging_logger.critical(e, exc_info=True)
		exit(1)
