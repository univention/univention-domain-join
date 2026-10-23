#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Registration of a DNS record for this machine on the UCS DC.

The domain join itself only creates the computer *account* (name and machine
password) in the UCS LDAP; no DNS record is created, because UCS only
generates zone records from the dnsEntryZoneForward/dnsEntryZoneReverse
attributes of the computer object. This module optionally fills them in.

Registration is intentionally restricted to machines with a statically
configured IP address: on DHCP clients a record written at join time would
go stale with the next lease, so it is skipped (and left to dynamic DNS,
if that is set up on the network).

All udm operations run on the DC via SSH with the same domain administrator
credentials the CLI was started with (--binddn of the admin, password from
the temporary /dev/shm password file created by authenticate_admin()).
"""

import logging
import os
import shutil
import subprocess
from typing import Optional

from univention_domain_join.utils.general import ssh
from univention_domain_join.utils.ldap import PW, get_machines_udm

userinfo_logger = logging.getLogger('userinfo')
log = logging.getLogger('debugging')


class DnsRecordRegistrar(object):
    """Registers forward (and, best effort, reverse) DNS records for this
    machine on the UCS DC, if the machine has a static IP address."""

    def register_dns(self, dc_ip: str, admin_username: str, admin_pw: str, ldap_base: str, admin_dn: str, domain: str) -> None:
        """Register the machine in the UCS DNS zone if its IP is static.

        Does nothing (with an explanation in the log) when the primary IP
        address is assigned via DHCP or the configuration method cannot be
        determined.
        """
        ip = self.get_primary_ip(dc_ip)
        if not ip:
            userinfo_logger.warn('Warning: could not determine the primary IP address of this machine. Skipping DNS registration.')
            return

        static = self.ip_is_static(ip)
        if static is None:
            userinfo_logger.warn(
                'Warning: could not determine whether %s is statically configured. '
                'Skipping DNS registration; add the record in the UMC if needed.' % (ip,)
            )
            return
        if not static:
            userinfo_logger.info(
                'The IP address %s of this machine is assigned via DHCP. '
                'Skipping DNS registration (--register-dns only registers static addresses).' % (ip,)
            )
            return

        self.register_forward_record(dc_ip, admin_username, admin_pw, ldap_base, admin_dn, domain, ip)
        self.register_reverse_record(dc_ip, admin_username, admin_pw, ldap_base, admin_dn, ip)

    def get_primary_ip(self, dc_ip: str) -> str:
        """Return the local source address used to reach the DC ('' on failure)."""
        try:
            output = subprocess.check_output(['ip', 'route', 'get', dc_ip], stderr=subprocess.STDOUT).decode()
            # e.g. "10.250.250.1 dev ens192 src 10.250.250.50 uid 0"
            return output.split()[output.split().index('src') + 1]
        except (subprocess.CalledProcessError, ValueError, IndexError) as e:
            log.debug("Determining the primary IP address failed: %s", e)
            return ''

    def ip_is_static(self, ip: str) -> Optional[bool]:
        """Return True if the address is statically configured, False if it
        comes from DHCP, None if the configuration method cannot be told."""
        device = self.get_device_for_ip(ip)
        if device and shutil.which('nmcli'):
            method = self.get_nm_ipv4_method(device)
            if method:
                return method == 'manual'
        return self.get_ifcfg_bootproto(ip, device)

    def get_device_for_ip(self, ip: str) -> str:
        """Return the network interface that owns the given address ('' if none)."""
        try:
            output = subprocess.check_output(['ip', '-o', 'addr', 'show'], stderr=subprocess.STDOUT).decode()
        except (OSError, subprocess.CalledProcessError):
            return ''
        for line in output.splitlines():
            parts = line.split()
            if 'inet' in parts and parts[parts.index('inet') + 1].split('/')[0] == ip:
                return parts[1]
        return ''

    def get_nm_ipv4_method(self, device: str) -> str:
        """Return the NetworkManager ipv4.method of the device's connection
        ('manual', 'auto', ...), or '' if it cannot be determined."""
        proc = subprocess.Popen(
            ['nmcli', '-g', 'GENERAL.CONNECTION', 'device', 'show', device],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = proc.communicate()
        connection = stdout.decode().strip()
        if proc.returncode != 0 or not connection or connection == '--':
            return ''
        proc = subprocess.Popen(
            ['nmcli', '-g', 'ipv4.method', 'connection', 'show', connection],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = proc.communicate()
        if proc.returncode != 0:
            return ''
        return stdout.decode().strip()

    def get_ifcfg_bootproto(self, ip: str, device: str) -> Optional[bool]:
        """Fallback for systems without NetworkManager: inspect the legacy
        ifcfg files in /etc/sysconfig/network-scripts."""
        candidates = []
        if device:
            candidates.append(os.path.join('/etc/sysconfig/network-scripts', 'ifcfg-%s' % device))
        try:
            candidates.extend(
                os.path.join('/etc/sysconfig/network-scripts', f)
                for f in os.listdir('/etc/sysconfig/network-scripts') if f.startswith('ifcfg-')
            )
        except OSError:
            return None
        for path in candidates:
            try:
                with open(path) as f:
                    content = f.read()
            except IOError:
                continue
            if 'IPADDR=%s' % ip not in content and 'IPADDR="%s"' % ip not in content:
                continue
            bootproto = ''
            for line in content.splitlines():
                if line.upper().startswith('BOOTPROTO='):
                    bootproto = line.partition('=')[2].strip().strip('"').lower()
            if bootproto in ('none', 'static'):
                return True
            if bootproto in ('dhcp', 'bootp'):
                return False
        return None

    def register_forward_record(self, dc_ip: str, admin_username: str, admin_pw: str, ldap_base: str, admin_dn: str, domain: str, ip: str) -> None:
        """Set the ip property and the forward zone entry on the machine's
        computer object via udm (over SSH on the DC)."""
        udm_type, dn = get_machines_udm(dc_ip, admin_username, admin_pw, admin_dn)
        userinfo_logger.info('Registering DNS record for %s in zone %s on the UCS DC' % (ip, domain))
        cmd = self.udm_dns_modify_command(udm_type, dn, admin_dn, admin_username, ip, 'dnsEntryZoneForward', 'zoneName=%s,cn=dns,%s' % (domain, ldap_base))
        if not self.run_udm(cmd, dc_ip, admin_username, admin_pw):
            userinfo_logger.warn('Warning: registering the forward DNS record failed. The join itself was successful; add the record in the UMC if needed.')

    def register_reverse_record(self, dc_ip: str, admin_username: str, admin_pw: str, ldap_base: str, admin_dn: str, ip: str) -> None:
        """Best effort PTR record in the /24 reverse zone of the address.
        Skipped silently if that reverse zone does not exist on the UCS DC."""
        try:
            udm_type, dn = get_machines_udm(dc_ip, admin_username, admin_pw, admin_dn)
        except LookupError:
            return
        reverse_zone = '.'.join(reversed(ip.split('.')[:3])) + '.in-addr.arpa'
        userinfo_logger.info('Registering PTR record for %s in zone %s on the UCS DC' % (ip, reverse_zone))
        cmd = self.udm_dns_modify_command(udm_type, dn, admin_dn, admin_username, ip, 'dnsEntryZoneReverse', 'zoneName=%s,cn=dns,%s' % (reverse_zone, ldap_base), set_ip=False)
        if not self.run_udm(cmd, dc_ip, admin_username, admin_pw):
            userinfo_logger.info('No matching reverse zone %s found on the UCS DC. Skipping the PTR record.' % reverse_zone)

    def udm_dns_modify_command(self, udm_type: str, dn: str, admin_dn: str, admin_username: str, ip: str, attribute: str, zone_value: str, set_ip: bool = True) -> list:
        """Build the udm modify command. The zone entry value contains a
        space ('<zone DN> <ip>'); the ssh() helper quotes each argument, so
        it arrives as a single value on the DC. --set (not --append) is
        used so that re-running the join is idempotent and does not
        produce 'value exists' warnings."""
        cmd = [
            '/usr/sbin/udm', udm_type, 'modify',
            '--binddn', admin_dn,
            '--bindpwdfile', PW(admin_username),
            '--dn', dn,
            '--set', '%s=%s %s' % (attribute, zone_value, ip),
        ]
        if set_ip:
            cmd += ['--set', 'ip=%s' % ip]
        return cmd

    def run_udm(self, cmd: list, dc_ip: str, admin_username: str, admin_pw: str) -> bool:
        """Run a udm command on the DC via SSH; return True on success."""
        ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ssh_process.communicate()
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
        return ssh_process.returncode == 0 and not stderr.decode().startswith('E: ')
