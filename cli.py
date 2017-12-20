from getpass import getpass
import argparse
import dns.resolver
import importlib
import logging
import os
import socket
import subprocess
import sys

OUTPUT_SINK = open(os.devnull, 'w')


def set_up_logging():
	global userinfo_logger
	global debugging_logger

	verbose_formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
	plain_formatter = logging.Formatter('%(message)s')

	if not os.path.exists('/var/log/univention/'):
		os.makedirs('/var/log/univention/')
	logfile_handler = logging.FileHandler('/var/log/univention/domain-join.log')
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


def get_domainname():
	try:
		domainname = socket.getfqdn().split('.', 1)[1]
	except IndexError:
		userinfo_logger.critical('The UCS domain is unknown. Please set your UCS domain as the domain name of this computer.')
		exit(1)
	return domainname


def get_master_of_domain(domain):
	resolver = dns.resolver.Resolver()
	try:
		response = resolver.query('_domaincontroller_master._tcp.%s.' % (domain,), 'SRV')
	except dns.resolver.NXDOMAIN:
		userinfo_logger.critical('DNS is not working correctly. Please make sure the DNS server of this computer is your domain controller Master.')
		exit(1)
	return response[0].target.to_text()


def get_joiner_for_this_distribution(master, skip_login_manager):
	distribution = get_distribution()
	try:
		distribution_join_module = importlib.import_module('distributions.%s' % (distribution.lower(),))
		master_pw = get_masters_root_password(master)
		masters_ucr_variables = get_ucr_variables_from_master(master, master_pw)
		return distribution_join_module.Joiner(masters_ucr_variables, master, master_pw, skip_login_manager)
	except ImportError:
		userinfo_logger.critical('The used distribution "%s" is not supported.' % (distribution,))
		exit(1)


def get_distribution():
	return subprocess.check_output(['lsb_release', '-is']).strip()


def get_masters_root_password(master):
	# TODO: Don't ask for the password if ssh works passwordless already.
	password = getpass(prompt='Please enter the password for root@%s: ' % (master,))
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', 'root@%s' % (master,), 'echo foo'],
		stdin=subprocess.PIPE, stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
	)
	ssh_process.communicate(password)
	if ssh_process.returncode != 0:
		userinfo_logger.critical('It\'s not possible to connect to the DC master via ssh, with the given password.')
		exit(1)
	return password


def get_ucr_variables_from_master(master, master_pw):
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', 'root@%s' % (master,), 'ucr shell | grep -v ^hostname='],
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
	set_up_logging()

	try:
		parser = argparse.ArgumentParser(
			description='Tool for joining a client computer into an UCS domain.'
		)
		parser.add_argument('--skip-login-manager', action='store_true', help='Do not configure the login manager.')
		args = parser.parse_args()

		domainname = get_domainname()
		master = get_master_of_domain(domainname)

		distribution_joiner = get_joiner_for_this_distribution(master, args.skip_login_manager)

		distribution_joiner.check_if_join_is_possible_without_problems()
		distribution_joiner.create_backup_of_config_files()
		distribution_joiner.join_domain()
	except Exception as e:
		userinfo_logger.critical('An unexpected error occurred. Please check %s for more information.' % (debugging_logger.handlers[0].baseFilename,))
		debugging_logger.critical(e, exc_info=True)
