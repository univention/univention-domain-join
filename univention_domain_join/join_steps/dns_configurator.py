#!/usr/bin/env python
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

from shutil import copyfile
import dns.resolver
import logging
import os
import subprocess

from univention_domain_join.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')


class DnsConfigurationException(Exception):
	pass


class DnsConfigurator(object):
	def __init__(self, nameservers, domain):
		self.nameservers = nameservers
		self.domain = domain

		if nameservers[0] == '':
			userinfo_logger.critical(
				'No name servers are configured in the UCR of the DC master.\n'
				'Please repair it, before running this tool again.'
			)
			raise DnsConfigurationException()
		if domain == '':
			userinfo_logger.critical(
				'No domain name is configured in the UCR of the DC master.\n'
				'Please repair it, before running this tool again.'
			)
			raise DnsConfigurationException()

		if DnsConfiguratorNetworkManager().works_on_this_system():
			self.working_configurator = DnsConfiguratorNetworkManager()
		else:
			self.working_configurator = DnsConfiguratorTrusty()

	def backup(self, backup_dir):
		self.working_configurator.backup(backup_dir)

	@execute_as_root
	def configure_dns(self):
		self.working_configurator.configure_dns(self.nameservers, self.domain)
		if self.domain.endswith('.local'):
			subprocess.check_call(['sed', '-i', '-E', 's/^(hosts: +.*) \\[NOTFOUND=return\\](.*) dns(.*)/\\1 dns \[NOTFOUND=return\]\\2\\3/', '/etc/nsswitch.conf'], close_fds=True)
		self.check_if_dns_works()

	def check_if_dns_works(self):
		resolver = dns.resolver.Resolver()
		try:
			resolver.query('_domaincontroller_master._tcp.%s.' % (self.domain,), 'SRV')
		except dns.resolver.NXDOMAIN:
			userinfo_logger.critical(
				'Setting up DNS did not work. Try removing any DNS settings in '
				'the network-manager and give this tool the IP address of the DC master.'
			)
			raise DnsConfigurationException()


class DnsConfiguratorTrusty(object):
	def __init__(self):
		self.sub_configurators = (DnsConfiguratorDHClient(), DnsConfiguratorOldNetworkManager(), DnsConfiguratorResolvconf())

	def backup(self, backup_dir):
		for configurator in self.sub_configurators:
			configurator.backup(backup_dir)

	def configure_dns(self, nameservers, domain):
		for configurator in self.sub_configurators:
			configurator.configure_dns(nameservers, domain)

class DnsConfiguratorSystemd(object):
	def works_on_this_system(self):
		ssh_process = subprocess.Popen(
			['service', 'systemd-resolved', 'status'],
			stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
		)
		ssh_process.communicate('')
		return ssh_process.returncode == 0

	@execute_as_root
	def backup(self, backup_dir):
		if os.path.isfile('/etc/systemd/resolved.conf'):
			userinfo_logger.warn('Warning: /etc/systemd/resolved.conf already exists.')
			os.makedirs(os.path.join(backup_dir, 'etc/systemd'))
			copyfile(
				'/etc/systemd/resolved.conf',
				os.path.join(backup_dir, 'etc/systemd/resolved.conf')
			)

	@execute_as_root
	def configure_dns(self, nameservers, domain):
		userinfo_logger.info('Writing /etc/systemd/resolved.conf')
		with open('/etc/systemd/resolved.conf', 'w') as conf_file:
			conf_file.write('[Resolve]\n')
			conf_file.write('DNS=%s\n' % (' '.join(nameservers),))
			conf_file.write('Domains=%s\n' % (domain,))

		userinfo_logger.info('Restarting systemd-resolved.')
		subprocess.check_call(['systemctl', 'restart', 'systemd-resolved'])


class DnsConfiguratorNetworkManager(object):
	def works_on_this_system(self):
		## could also check lsb_release -sr here instead
		p = subprocess.Popen(
			['nmcli', '-v'],
			stdout=subprocess.PIPE, stderr=subprocess.PIPE
		)
		stdout, stderr = p.communicate()
		if p.returncode != 0:
			return False
		nmcli_version = stdout.split()[-1]
		p = subprocess.Popen(
			['dpkg', '--compare-versions', nmcli_version, 'gt', '1']
		)
		p.wait()
		return p.returncode == 0

	@execute_as_root
	def backup(self, backup_dir):
		## TODO: where does nmcli store the DNS settings?
		return

	@execute_as_root
	def configure_dns(self, nameservers, domain):
		p = subprocess.Popen(
			['nmcli', '-t', '-f', 'NAME,UUID,DEVICE', 'connection', 'show', '--active'],
			stdout=subprocess.PIPE, stderr=subprocess.PIPE
		)
		stdout, stderr = p.communicate()
		if p.returncode != 0:
			raise DnsConfigurationException()
		for line in stdout.splitlines():
			conn_name, conn_uuid, conn_dev = line.split(':')
			userinfo_logger.info('Configuring ipv4 DNS servers for %s.' % conn_dev)
			p = subprocess.Popen(
				['nmcli', 'connection', 'modify', conn_uuid,
				'ipv4.dns', " ".join(filter(lambda x: x, nameservers)),
				'ipv4.ignore-auto-dns', 'yes',
				'ipv4.dns-search' , domain]
			)
			p.wait()
			userinfo_logger.info('Applying new settings to %s.' % conn_dev)
			p = subprocess.Popen(
				['nmcli', 'connection', 'down', conn_uuid]
			)
			p.wait()
			p = subprocess.Popen(
				['nmcli', 'connection', 'up', conn_uuid]
			)
			p.wait()

class DnsConfiguratorOldNetworkManager(object):
	@execute_as_root
	def backup(self, backup_dir):
		p = subprocess.Popen(
			['nmcli', '-t', '-f', 'NAME,UUID', 'connection', 'list'],
			stdout=subprocess.PIPE, stderr=subprocess.PIPE
		)
		stdout, stderr = p.communicate()
		if p.returncode != 0:
			raise DnsConfigurationException()
		for line in stdout.splitlines():
			conn_name, conn_uuid= line.split(':')
			fn = '/etc/NetworkManager/system-connections/%s' % conn_name
			fn_backup = os.path.join(backup_dir, fn[1:])
			if os.path.isfile(fn):
				userinfo_logger.info('Backing up %s' % fn)
				os.makedirs(os.path.join(backup_dir, 'etc/NetworkManager/system-connections'))
				copyfile(
					fn,
					fn_backup
				)
				os.chmod(fn_backup, 0600)

	@execute_as_root
	def configure_dns(self, nameservers, domain):
		ns_string = ';'.join(filter(lambda x: x, nameservers))+';'
		import ConfigParser
		p = subprocess.Popen(
			['nmcli', '-t', '-f', 'NAME,UUID', 'connection', 'list'],
			stdout=subprocess.PIPE, stderr=subprocess.PIPE
		)
		stdout, stderr = p.communicate()
		if p.returncode != 0:
			raise DnsConfigurationException()
		for line in stdout.splitlines():
			conn_name, conn_uuid= line.split(':')
			fn = '/etc/NetworkManager/system-connections/%s' % conn_name
			if os.path.isfile(fn):
				Config = ConfigParser.ConfigParser()
				Config.read(fn)
				Config.set('ipv4', 'dns', ns_string)
				Config.set('ipv4', 'dns-search', '')
				Config.set('ipv4', 'ignore-auto-dns', 'true')
				with open(fn, 'w') as f:
					Config.write(f)
		subprocess.check_call(['service', 'network-manager', 'restart'])

class DnsConfiguratorDHClient(object):
	@execute_as_root
	def backup(self, backup_dir):
		if os.path.isfile('/etc/dhcp/dhclient.conf'):
			os.makedirs(os.path.join(backup_dir, 'etc/dhcp'))
			copyfile(
				'/etc/dhcp/dhclient.conf',
				os.path.join(backup_dir, 'etc/dhcp/dhclient.conf')
			)

	@execute_as_root
	def configure_dns(self, nameservers, domain):
		ns_string = " ".join(filter(lambda x: x, nameservers))
		p = subprocess.Popen(
			['grep', '-q', '^prepend domain-name-servers %s' % ns_string,
			'/etc/dhcp/dhclient.conf']
		)
		p.wait()
		if p.returncode == 0:
			userinfo_logger.info('"prepend domain-name-servers" already in /etc/dhcp/dhclient.conf')
			return
		userinfo_logger.info('Adjusting /etc/dhcp/dhclient.conf')
		with open('/etc/dhcp/dhclient.conf', 'a') as conf_file:
			conf_file.write('\nprepend domain-name-servers %s\n' % (ns_string,))


class DnsConfiguratorResolvconf(object):
	@execute_as_root
	def backup(self, backup_dir):
		if os.path.isfile('/etc/resolvconf/resolv.conf.d/base'):
			userinfo_logger.warn('Warning: /etc/resolvconf/resolv.conf.d/base already exists.')
			os.makedirs(os.path.join(backup_dir, 'etc/resolvconf/resolv.conf.d'))
			copyfile(
				'/etc/resolvconf/resolv.conf.d/base',
				os.path.join(backup_dir, 'etc/resolvconf/resolv.conf.d/base')
			)

	@execute_as_root
	def configure_dns(self, nameservers, domain):
		userinfo_logger.info('Writing /etc/resolvconf/resolv.conf.d/base')
		with open('/etc/resolvconf/resolv.conf.d/base', 'w') as conf_file:
			for nameserver in nameservers:
				if nameserver != '':
					conf_file.write('nameserver %s\n' % (nameserver,))
			conf_file.write('domain %s' % (domain,))

		userinfo_logger.info('Applying new resolvconf settings.')
		subprocess.check_call(['service', 'resolvconf', 'stop'])
		subprocess.check_call(['service', 'resolvconf', 'start'])
