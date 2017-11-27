from getpass import getpass
import argparse
import importlib
import os
import paramiko
import subprocess

OUTPUT_SINK = open(os.devnull, 'w')

# TODO: Make sure dependent packets are installed in the Debian package.
# TODO: Is it required  for security to do ssh_client.load_system_host_keys('/root/.ssh/known_hosts')
#       instead of ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) ?
# TODO: Should joining via a DC slave be possible?
# TODO: Add join_steps backup functions.


def check_if_dns_is_set_up_correctly(master_ip):
	# TODO: Write an /etc/hosts entry instead?
	# TODO: Is 'host' usable across distributions?
	master_dns_works = 0 == subprocess.call(
		['host', master_ip], stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
	)
	assert master_dns_works, 'The DC master is not set as DNS server.'


def get_joiner_for_this_distribution(master_ip):
	distribution = get_distribution()
	try:
		distribution_join_module = importlib.import_module('distributions.%s' % (distribution.lower(),))
		master_pw = get_masters_root_password(master_ip)
		masters_ucr_variables = get_ucr_variables_from_master(master_ip, master_pw)
		return distribution_join_module.Joiner(masters_ucr_variables, master_ip, master_pw)
	except ImportError:
		raise Exception('The used distribution "%s" is not supported.' % (distribution,))


def get_distribution():
	return subprocess.check_output(['lsb_release', '-is']).strip()


def get_masters_root_password(master_ip):
	password = getpass(prompt='Please enter the password for root@%s: ' % (master_ip,))
	with paramiko.SSHClient() as ssh_client:
		ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
			ssh_client.connect(master_ip, username='root', password=password)
		except paramiko.ssh_exception.BadAuthenticationType:
			raise Exception('It\'s not possible to connect to the DC master via ssh, with the given password.')
	return password


def get_ucr_variables_from_master(master_ip, master_pw):
	with paramiko.SSHClient() as ssh_client:
		ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh_client.connect(master_ip, username='root', password=master_pw)
		stdin, stdout, stderr = ssh_client.exec_command('ucr shell | grep -v ^hostname=')
		if stdout.channel.recv_exit_status() != 0:
			raise Exception('Fetching the UCR variables from the master failed.')
		ucr_variables = {}
		for raw_ucr_variable in stdout:
			key, value = raw_ucr_variable.strip().split('=', 1)
			ucr_variables[key] = value
	return ucr_variables


if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='Tool for joining a client computer into an UCS domain.'
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
