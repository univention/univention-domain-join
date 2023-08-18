#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

import configparser
import logging
import os
import subprocess
from shutil import copyfile
from typing import List, Tuple

import dns.resolver

from univention_domain_join.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')


class DnsConfigurationException(Exception):
    pass


class DnsConfigurator(object):
    def __init__(self, nameservers: List[str], domain: str) -> None:
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

        self.working_configurator: BaseDnsConfigurator = DnsConfiguratorNetworkManager() if DnsConfiguratorNetworkManager().works_on_this_system() else DnsConfiguratorTrusty()

    def backup(self, backup_dir: str) -> None:
        self.working_configurator.backup(backup_dir)

    @execute_as_root
    def configure_dns(self) -> None:
        self.working_configurator.configure_dns(self.nameservers, self.domain)
        if self.domain.endswith('.local'):
            subprocess.check_output([
                'sed', '-i', '-E',
                r's/^(hosts: +.*)( mdns4_minimal)(.*)\[NOTFOUND=return\](.*)( dns)(.*)/\1\5\2\3[NOTFOUND=return]\4\6/',
                '/etc/nsswitch.conf'
            ], stderr=subprocess.STDOUT)
        self.check_if_dns_works()

    def check_if_dns_works(self) -> None:
        resolver = dns.resolver.Resolver()
        try:
            resolver.query('_domaincontroller_master._tcp.%s.' % (self.domain,), 'SRV')
        except dns.resolver.NXDOMAIN:
            userinfo_logger.critical(
                'Setting up DNS did not work. Try removing any DNS settings in '
                'the network-manager and give this tool the IP address of the DC master.'
            )
            raise DnsConfigurationException()


class BaseDnsConfigurator(object):
    def backup(self, backup_dir: str) -> None:
        raise NotImplementedError()

    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        raise NotImplementedError()


class DnsConfiguratorTrusty(BaseDnsConfigurator):
    def __init__(self) -> None:
        self.sub_configurators: Tuple[BaseDnsConfigurator, ...] = (DnsConfiguratorDHClient(), DnsConfiguratorOldNetworkManager(), DnsConfiguratorResolvconf())

    def backup(self, backup_dir: str) -> None:
        for configurator in self.sub_configurators:
            configurator.backup(backup_dir)

    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        for configurator in self.sub_configurators:
            configurator.configure_dns(nameservers, domain)


class DnsConfiguratorSystemd(BaseDnsConfigurator):
    def works_on_this_system(self) -> bool:
        cmd = ['service', 'systemd-resolved', 'status']
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        _, stderr = proc.communicate()
        logging.getLogger('debugging').debug("%r returned %d: %s", cmd, proc.returncode, stderr.decode())
        return proc.returncode == 0

    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        if os.path.isfile('/etc/systemd/resolved.conf'):
            userinfo_logger.warn('Warning: /etc/systemd/resolved.conf already exists.')
            os.makedirs(os.path.join(backup_dir, 'etc/systemd'), exist_ok=True)
            copyfile(
                '/etc/systemd/resolved.conf',
                os.path.join(backup_dir, 'etc/systemd/resolved.conf')
            )

    @execute_as_root
    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        userinfo_logger.info('Writing /etc/systemd/resolved.conf')
        with open('/etc/systemd/resolved.conf', 'w') as conf_file:
            conf_file.write('[Resolve]\n')
            conf_file.write('DNS=%s\n' % (' '.join(nameservers),))
            conf_file.write('Domains=%s\n' % (domain,))

        userinfo_logger.info('Restarting systemd-resolved.')
        subprocess.check_output(['systemctl', 'restart', 'systemd-resolved'], stderr=subprocess.STDOUT)


class DnsConfiguratorNetworkManager(BaseDnsConfigurator):
    def works_on_this_system(self) -> bool:
        # could also check lsb_release -sr here instead
        proc = subprocess.Popen(
            ['nmcli', '-v'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = proc.communicate()
        logging.getLogger('debugging').debug("%r returned %d: %s", proc.args, proc.returncode, stderr.decode())
        if proc.returncode != 0:
            return False
        nmcli_version = stdout.split()[-1]
        p = subprocess.Popen(
            ['dpkg', '--compare-versions', nmcli_version, 'gt', '1'],
        )
        return p.wait() == 0

    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        # TODO: where does nmcli store the DNS settings?
        return

    @execute_as_root
    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        p = subprocess.Popen(
            ['nmcli', '-t', '-f', 'NAME,UUID,DEVICE', 'connection', 'show', '--active'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        logging.getLogger('debugging').debug("%r returned %d: %s", p.args, p.returncode, stderr.decode())
        if p.returncode != 0:
            raise DnsConfigurationException()
        for line in stdout.decode().splitlines():
            conn_name, conn_uuid, conn_dev = line.split(':')
            userinfo_logger.info('Configuring ipv4 DNS servers for %s.' % conn_dev)
            subprocess.call([
                'nmcli', 'connection', 'modify', conn_uuid,
                'ipv4.dns', " ".join(filter(lambda x: x, nameservers)).encode(),
                'ipv4.ignore-auto-dns', 'yes',
                'ipv4.dns-search', domain.encode()
            ])
            userinfo_logger.info('Applying new settings to %s.' % conn_dev)
            subprocess.call(
                ['nmcli', 'connection', 'down', conn_uuid.encode()]
            )
            subprocess.call(
                ['nmcli', 'connection', 'up', conn_uuid.encode()]
            )


class DnsConfiguratorOldNetworkManager(BaseDnsConfigurator):
    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        p = subprocess.Popen(
            ['nmcli', '-t', '-f', 'NAME,UUID', 'connection', 'list'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        logging.getLogger('debugging').debug("%r returned %d: %s", p.args, p.returncode, stderr.decode())
        if p.returncode != 0:
            raise DnsConfigurationException()
        for line in stdout.splitlines():
            conn_name, conn_uuid = line.decode().split(':')
            fn = '/etc/NetworkManager/system-connections/%s' % conn_name
            fn_backup = os.path.join(backup_dir, fn[1:])
            if os.path.isfile(fn):
                userinfo_logger.info('Backing up %s' % fn)
                os.makedirs(os.path.join(backup_dir, 'etc/NetworkManager/system-connections'), exist_ok=True)
                copyfile(
                    fn,
                    fn_backup
                )
                os.chmod(fn_backup, 0o600)

    @execute_as_root
    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        ns_string = ';'.join(filter(lambda x: x, nameservers)) + ';'
        p = subprocess.Popen(
            ['nmcli', '-t', '-f', 'NAME,UUID', 'connection', 'list'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        logging.getLogger('debugging').debug("%r returned %d: %s", p.args, p.returncode, stderr.decode())
        if p.returncode != 0:
            raise DnsConfigurationException()
        for line in stdout.splitlines():
            conn_name, conn_uuid = line.decode().split(':')
            fn = '/etc/NetworkManager/system-connections/%s' % conn_name
            if os.path.isfile(fn):
                Config = configparser.ConfigParser()
                Config.read(fn)
                Config.set('ipv4', 'dns', ns_string)
                Config.set('ipv4', 'dns-search', '')
                Config.set('ipv4', 'ignore-auto-dns', 'true')
                with open(fn, 'w') as f:
                    Config.write(f)
        subprocess.check_output(['service', 'network-manager', 'restart'], stderr=subprocess.STDOUT)


class DnsConfiguratorDHClient(BaseDnsConfigurator):
    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        if os.path.isfile('/etc/dhcp/dhclient.conf'):
            os.makedirs(os.path.join(backup_dir, 'etc/dhcp'), exist_ok=True)
            copyfile(
                '/etc/dhcp/dhclient.conf',
                os.path.join(backup_dir, 'etc/dhcp/dhclient.conf')
            )

    @execute_as_root
    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        ns_string = " ".join(filter(lambda x: x, nameservers))
        p = subprocess.Popen([
            'grep', '-q', '^prepend domain-name-servers %s' % ns_string,
            '/etc/dhcp/dhclient.conf'
        ], stderr=subprocess.PIPE)
        _, stderr = p.communicate()
        logging.getLogger('debugging').debug("%r returned %d: %s", p.args, p.returncode, stderr.decode())
        if p.returncode == 0:
            userinfo_logger.info('"prepend domain-name-servers" already in /etc/dhcp/dhclient.conf')
            return
        userinfo_logger.info('Adjusting /etc/dhcp/dhclient.conf')
        with open('/etc/dhcp/dhclient.conf', 'a') as conf_file:
            conf_file.write('\nprepend domain-name-servers %s\n' % (ns_string,))


class DnsConfiguratorResolvconf(BaseDnsConfigurator):
    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        if os.path.isfile('/etc/resolvconf/resolv.conf.d/base'):
            userinfo_logger.warn('Warning: /etc/resolvconf/resolv.conf.d/base already exists.')
            os.makedirs(os.path.join(backup_dir, 'etc/resolvconf/resolv.conf.d'), exist_ok=True)
            copyfile(
                '/etc/resolvconf/resolv.conf.d/base',
                os.path.join(backup_dir, 'etc/resolvconf/resolv.conf.d/base')
            )

    @execute_as_root
    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        userinfo_logger.info('Writing /etc/resolvconf/resolv.conf.d/base')
        with open('/etc/resolvconf/resolv.conf.d/base', 'w') as conf_file:
            for nameserver in nameservers:
                if nameserver != '':
                    conf_file.write('nameserver %s\n' % (nameserver,))
            conf_file.write('domain %s' % (domain,))

        userinfo_logger.info('Applying new resolvconf settings.')
        subprocess.check_output(['service', 'resolvconf', 'stop'], stderr=subprocess.STDOUT)
        subprocess.check_output(['service', 'resolvconf', 'start'], stderr=subprocess.STDOUT)
