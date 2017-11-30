from getpass import getpass
import argparse
import importlib
import os
import subprocess

OUTPUT_SINK = open(os.devnull, 'w')


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
	# TODO: Don't ask for the password if ssh works passwordless already.
	password = getpass(prompt='Please enter the password for root@%s: ' % (master_ip,))
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', 'root@%s' % (master_ip,), 'echo foo'],
		stdin=subprocess.PIPE, stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
	)
	ssh_process.communicate(password)
	if ssh_process.returncode != 0:
		raise Exception('It\'s not possible to connect to the DC master via ssh, with the given password.')
	return password


def get_ucr_variables_from_master(master_ip, master_pw):
	ssh_process = subprocess.Popen(
		['sshpass', '-d0', 'ssh', '-o', 'StrictHostKeyChecking=no', 'root@%s' % (master_ip,), 'ucr shell | grep -v ^hostname='],
		stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	stdout, stderr = ssh_process.communicate(master_pw)
	if ssh_process.returncode != 0:
		raise Exception('Fetching the UCR variables from the master failed.')
	ucr_variables = {}
	for raw_ucr_variable in stdout.splitlines():
		key, value = raw_ucr_variable.strip().split('=', 1)
		ucr_variables[key] = value
	return ucr_variables


if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='Tool for joining a client computer into an UCS domain.'
	)
	parser.add_argument('--force', action='store_true', help='Force the execution of the join steps. Manual fixing will probably be required after this.')
	parser.add_argument('master_ip', help='IP of the DC master.')
	args = parser.parse_args()

	distribution_joiner = get_joiner_for_this_distribution(args.master_ip)

	if not args.force:
		distribution_joiner.check_if_join_is_possible_without_problems()
	distribution_joiner.create_backup_of_config_files()
	distribution_joiner.join_domain()
