from getpass import getpass
import argparse
import importlib
import os
import subprocess

OUTPUT_SINK = open(os.devnull, 'w')

# TODO: Make sure dependent packets are installed in the Debian package.
# TODO: Back up (with timestamp) all files that will be touched into /var/univention/backup .
#       Leaving out any old LDAP objects.
# TODO: Check for any conflicts beforehand (checks) and abort if there is any.


def check_if_dns_is_set_up_correctly(master_ip):
	# TODO: Is 'host' usable across distributions?
	master_dns_works = 0 == subprocess.call(
		['host', master_ip], stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
	)
	assert master_dns_works, 'The DC master is not set as DNS server.'


def get_joiner_for_this_distribution(master_ip):
	master_pw = get_masters_root_password(master_ip)
	masters_ucr_variables = get_ucr_variables_from_master(master_ip, master_pw)

	distribution = get_distribution()
	try:
		distribution_join_module = importlib.import_module('distributions.%s' % (distribution.lower(),))
	except ImportError:
		raise Exception('The used distribution "%s" is not supported.' % (distribution,))
	return distribution_join_module.Joiner(
		masters_ucr_variables, master_ip, master_pw
	)


def get_distribution():
	return subprocess.check_output(['lsb_release', '-is']).strip()


def get_masters_root_password(master_ip):
	return getpass(prompt='Please enter the password for root@%s: ' % (master_ip,))
	# TODO: Check if password works.


def get_ucr_variables_from_master(master_ip, master_pw):
	masters_ucr_output = subprocess.check_output(
		['ssh', 'root@%s' % (master_ip,), 'ucr shell | grep -v ^hostname='],
	).splitlines()
	ucr_variables = {}
	for raw_ucr_variable in masters_ucr_output:
		key, value = raw_ucr_variable.split('=', 1)
		ucr_variables[key] = value
	return ucr_variables


if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='Tool for joining an Ubuntu client into an UCS domain.'
	)
	parser.add_argument('--force', action='store_true', help='Force the execution of the join steps, even if this overwrites configuration files.')
	parser.add_argument('master_ip', help='IP of the DC master.')
	args = parser.parse_args()

	check_if_dns_is_set_up_correctly(args.master_ip)
	distribution_joiner = get_joiner_for_this_distribution(args.master_ip)

	if not args.force:
		distribution_joiner.check_if_join_is_possible_without_problems()
	distribution_joiner.create_backup_of_config_files()
	distribution_joiner.join_domain()
