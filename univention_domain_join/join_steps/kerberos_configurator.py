#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Write /etc/krb5.conf and synchronize the client's clock with the DC.

Kerberos requires the client and DC clocks to be within 5 minutes of each
other, so a one-shot time sync against the DC finishes this step.
"""

import logging
import os
import shutil
import subprocess
from shutil import copyfile

from univention_domain_join.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')


class ConflictChecker(object):
    """Detects pre-existing configuration that this step would overwrite."""

    def config_file_exists(self) -> bool:
        """Return True (and warn) if /etc/krb5.conf already exists."""
        if os.path.isfile('/etc/krb5.conf'):
            userinfo_logger.warn('Warning: /etc/krb5.conf already exists.')
            return True
        return False


class KerberosConfigurator(ConflictChecker):
    """Writes /etc/krb5.conf for the UCS realm and syncs the clock with the DC."""

    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        """Back up an existing /etc/krb5.conf."""
        if self.config_file_exists():
            os.makedirs(os.path.join(backup_dir, 'etc'), exist_ok=True)
            copyfile(
                '/etc/krb5.conf',
                os.path.join(backup_dir, 'etc/krb5.conf')
            )

    def configure_kerberos(self, kerberos_realm: str, ldap_master: str, ldap_server_name: str, is_samba_dc: bool, dc_ip: str) -> None:
        """Write the Kerberos config, then synchronize the time with the DC."""
        self.write_config_file(kerberos_realm, ldap_master, ldap_server_name, is_samba_dc)
        self.synchronize_time_with_master(dc_ip)

    @execute_as_root
    def write_config_file(self, kerberos_realm: str, ldap_master: str, ldap_server_name: str, is_samba_dc: bool) -> None:
        """Write /etc/krb5.conf.

        The kpasswd service lives on the Samba DC itself if we joined
        against one, otherwise on the UCS master.
        """
        userinfo_logger.info('Writing /etc/krb5.conf ')
        if is_samba_dc:
            kpasswd_name = ldap_server_name
        else:
            kpasswd_name = ldap_master
        config = \
            '[libdefaults]\n' \
            '    default_realm = %(kerberos_realm)s\n' \
            '    kdc_timesync = 1\n' \
            '    ccache_type = 4\n' \
            '    forwardable = true\n' \
            '    proxiable = true\n' \
            '    default_tkt_enctypes = arcfour-hmac-md5 des-cbc-md5 des3-hmac-sha1 des-cbc-crc des-cbc-md4 des3-cbc-sha1 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96\n' \
            '    permitted_enctypes = des3-hmac-sha1 des-cbc-crc des-cbc-md4 des-cbc-md5 des3-cbc-sha1 arcfour-hmac-md5 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96\n' \
            '    allow_weak_crypto=true\n' \
            '    rdns = false\n' \
            '\n' \
            '[realms]\n' \
            '%(kerberos_realm)s = {\n' \
            '   kdc = %(ldap_server_name)s\n' \
            '   admin_server = %(ldap_server_name)s\n' \
            '   kpasswd_server = %(kpasswd_name)s\n' \
            '}\n' \
            % {
                'kerberos_realm': kerberos_realm,
                'ldap_server_name': ldap_server_name,
                'kpasswd_name': kpasswd_name
            }
        with open('/etc/krb5.conf', 'w') as conf_file:
            conf_file.write(config)

    @execute_as_root
    def synchronize_time_with_master(self, dc_ip: str) -> None:
        """Synchronize the clock with the DC, warning (not failing) on errors.

        Runs at the very end of the join, when everything else is already
        configured, so a failed time sync must not abort the whole join.
        """
        userinfo_logger.info('Synchronizing time with the DC')
        try:
            self.sync_time(dc_ip)
        except subprocess.CalledProcessError as e:
            # Don't fail the whole join at the last step because of this;
            # everything else is already configured at this point.
            userinfo_logger.warn(
                'Warning: time synchronization with the DC failed (%s).\n'
                'Kerberos requires the clocks of the client and the DC to be within 5 minutes of each other.' % (e,)
            )

    def sync_time(self, dc_ip: str) -> None:
        """One-shot time sync against the DC: ntpdate → sntp → chronyd.

        ntpdate is deprecated and not shipped on modern RPM distributions,
        so the first available tool wins. If chronyd is already running as
        a service, a one-shot `chronyd -q` would fail; chronyc is used to
        steer the running daemon instead.
        """
        # ntpdate is deprecated and not shipped on modern RPM distributions,
        # so try the available tools in order.
        if shutil.which('ntpdate'):
            cmds = [['ntpdate', '-b', '-u', '-t', '5', dc_ip]]
        elif shutil.which('sntp'):
            cmds = [['sntp', '-sS', dc_ip]]
        elif shutil.which('chronyd'):
            if subprocess.call(['chronyc', 'tracking'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                # chronyd is already running; a one-shot `chronyd -q` would
                # fail, so talk to the running daemon via chronyc instead.
                cmds = [
                    ['chronyc', 'add server %s iburst' % (dc_ip,)],
                    ['chronyc', 'burst 4/4'],
                    ['chronyc', 'makestep'],
                ]
            else:
                cmds = [['chronyd', '-q', 'server %s iburst' % (dc_ip,)]]
        else:
            userinfo_logger.warn('Warning: no NTP client found (tried ntpdate, sntp, chronyd). Skipping time synchronization.')
            return
        for cmd in cmds:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
