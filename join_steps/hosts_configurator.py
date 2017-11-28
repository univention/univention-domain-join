from __future__ import print_function
from shutil import copyfile
import os
import subprocess
import sys

OUTPUT_SINK = open(os.devnull, 'w')


class HostsConfigurator(object):
	def backup(self, backup_dir):
		if not os.path.exists(os.path.join(backup_dir, 'etc')):
			os.makedirs(os.path.join(backup_dir, 'etc'))
			copyfile(
				'/etc/hosts',
				os.path.join(backup_dir, 'etc/hosts')
			)

	def configure_hosts(self, master_ip, ldap_master):
		self.setup_dns_if_not_working(master_ip, ldap_master)

	def setup_dns_if_not_working(self, master_ip, ldap_master):
		if self.master_dns_works(ldap_master):
			return
		self.add_hosts_entry(master_ip, ldap_master)

	def master_dns_works(self, ldap_master):
		return 0 == subprocess.call(
			['ping', '-c1', ldap_master], stdout=OUTPUT_SINK, stderr=OUTPUT_SINK
		)

	def add_hosts_entry(self, ip, name):
			print('Writing entry for the master to /etc/hosts ', end='... ')
			sys.stdout.flush()

			with open('/etc/hosts', 'a') as hosts_file:
				hosts_file.write('%s %s\n' % (ip, name))

			print('Done.')
