#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Point the client's DNS at the UCS DCs (only used with --force-ucs-dns).

Prefers NetworkManager (nmcli), which manages DNS on most RPM installs,
and falls back to writing /etc/resolv.conf directly when NetworkManager
is not running. Replaces the resolvconf/dhclient based configuration of
the Debian/Ubuntu version.
"""

import logging
import shutil
import subprocess
from shutil import copyfile
from typing import List

import dns.resolver

from univention_domain_join.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')


class DnsConfigurationException(Exception):
    """Raised when DNS cannot be configured or does not work afterwards."""


class DnsConfigurator(object):
    """Configure the client's DNS through whichever backend works on this system.

    Uses NetworkManager if available, otherwise writes /etc/resolv.conf
    directly. Validates the UCR-provided nameservers/domain on creation.
    """

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

        self.working_configurator: BaseDnsConfigurator = DnsConfiguratorNetworkManager() if DnsConfiguratorNetworkManager().works_on_this_system() else DnsConfiguratorResolvConf()

    def backup(self, backup_dir: str) -> None:
        """Back up the DNS configuration via the selected backend."""
        self.working_configurator.backup(backup_dir)

    @execute_as_root
    def configure_dns(self) -> None:
        """Apply the UCS nameservers, fix mdns ordering, then verify DNS works."""
        self.working_configurator.configure_dns(self.nameservers, self.domain)
        self.fix_mdns_nsswitch()
        self.check_if_dns_works()

    @execute_as_root
    def fix_mdns_nsswitch(self) -> None:
        """Move mdns4_minimal after dns in nsswitch.conf for .local domains.

        Only relevant when the UCS domain ends in .local; otherwise a
        no-op.
        """
        # With a .local domain, mdns must not shadow regular DNS lookups.
        # This mirrors the upstream fix; RPM systems ship mdns4_minimal
        # through nss-mdns in /etc/nsswitch.conf as well.
        if not self.domain.endswith('.local'):
            return
        try:
            with open('/etc/nsswitch.conf') as f:
                content = f.read()
        except IOError:
            return
        if 'mdns4_minimal' not in content:
            return
        subprocess.check_output([
            'sed', '-i', '-E',
            r's/^(hosts: +.*)( mdns4_minimal)(.*)\[NOTFOUND=return\](.*)( dns)(.*)/\1\5\2\3[NOTFOUND=return]\4\6/',
            '/etc/nsswitch.conf'
        ], stderr=subprocess.STDOUT)

    def check_if_dns_works(self) -> None:
        """Verify the UCS SRV record resolves with the new settings; raise if not."""
        resolver = dns.resolver.Resolver()
        query = getattr(resolver, 'resolve', None) or resolver.query
        try:
            query('_domaincontroller_master._tcp.%s.' % (self.domain,), 'SRV')
        except dns.resolver.NXDOMAIN:
            userinfo_logger.critical(
                'Setting up DNS did not work. Try removing any DNS settings in '
                'the network-manager and give this tool the IP address of the DC master.'
            )
            raise DnsConfigurationException()


class BaseDnsConfigurator(object):
    """Interface for the DNS backend implementations."""

    def backup(self, backup_dir: str) -> None:
        raise NotImplementedError()

    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        raise NotImplementedError()


class DnsConfiguratorNetworkManager(BaseDnsConfigurator):
    """Set DNS servers via nmcli on all active NetworkManager connections.

    The common case on RPM desktop and server installs, where
    NetworkManager owns /etc/resolv.conf.
    """

    def works_on_this_system(self) -> bool:
        """Return True if nmcli exists and NetworkManager has active connections."""
        if not shutil.which('nmcli'):
            return False
        proc = subprocess.Popen(
            ['nmcli', '-t', '-f', 'NAME,UUID,DEVICE', 'connection', 'show', '--active'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        _, stderr = proc.communicate()
        logging.getLogger('debugging').debug("%r returned %d: %s", proc.args, proc.returncode, stderr.decode())
        return proc.returncode == 0

    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        # NetworkManager keeps the DNS settings inside its connection
        # profiles; nothing file based to back up here.
        return

    @execute_as_root
    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        """Set the UCS nameservers/search domain on every active connection and reapply."""
        p = subprocess.Popen(
            ['nmcli', '-t', '-f', 'NAME,UUID,DEVICE', 'connection', 'show', '--active'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        logging.getLogger('debugging').debug("%r returned %d: %s", p.args, p.returncode, stderr.decode())
        if p.returncode != 0:
            raise DnsConfigurationException()
        for line in stdout.decode().splitlines():
            conn_name, conn_uuid, conn_dev = line.rsplit(':', 2)
            userinfo_logger.info('Configuring ipv4 DNS servers for %s.' % conn_dev)
            subprocess.call([
                'nmcli', 'connection', 'modify', conn_uuid,
                'ipv4.dns', " ".join(filter(lambda x: x, nameservers)),
                'ipv4.ignore-auto-dns', 'yes',
                'ipv4.dns-search', domain
            ])
            userinfo_logger.info('Applying new settings to %s.' % conn_dev)
            subprocess.call(['nmcli', 'connection', 'down', conn_uuid])
            subprocess.call(['nmcli', 'connection', 'up', conn_uuid])


class DnsConfiguratorResolvConf(BaseDnsConfigurator):
    """Fallback for systems without NetworkManager: write /etc/resolv.conf
    directly. Only suitable when nothing else manages the file."""

    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        """Back up /etc/resolv.conf if it is a regular file (not a symlink)."""
        import os
        if os.path.isfile('/etc/resolv.conf') and not os.path.islink('/etc/resolv.conf'):
            os.makedirs(os.path.join(backup_dir, 'etc'), exist_ok=True)
            copyfile('/etc/resolv.conf', os.path.join(backup_dir, 'etc/resolv.conf'))

    @execute_as_root
    def configure_dns(self, nameservers: List[str], domain: str) -> None:
        """Write the UCS nameservers and search domain to /etc/resolv.conf."""
        userinfo_logger.info('Writing /etc/resolv.conf')
        with open('/etc/resolv.conf', 'w') as conf_file:
            for nameserver in nameservers:
                if nameserver != '':
                    conf_file.write('nameserver %s\n' % (nameserver,))
            conf_file.write('search %s\n' % (domain,))
