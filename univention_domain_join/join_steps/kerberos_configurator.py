#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

import logging
import os
import subprocess
from shutil import copyfile

from univention_domain_join.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')


class ConflictChecker(object):
    def config_file_exists(self) -> bool:
        if os.path.isfile('/etc/krb5.conf'):
            userinfo_logger.warn('Warning: /etc/krb5.conf already exists.')
            return True
        return False


class KerberosConfigurator(ConflictChecker):
    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        if self.config_file_exists():
            os.makedirs(os.path.join(backup_dir, 'etc'), exist_ok=True)
            copyfile(
                '/etc/krb5.conf',
                os.path.join(backup_dir, 'etc/krb5.conf')
            )

    def configure_kerberos(self, kerberos_realm: str, ldap_master: str, ldap_server_name: str, is_samba_dc: bool, dc_ip: str) -> None:
        self.write_config_file(kerberos_realm, ldap_master, ldap_server_name, is_samba_dc)
        self.synchronize_time_with_master(dc_ip)

    @execute_as_root
    def write_config_file(self, kerberos_realm: str, ldap_master: str, ldap_server_name: str, is_samba_dc: bool) -> None:
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
        userinfo_logger.info('Synchronizing time with the DC')
        subprocess.check_output(
            ['ntpdate', '-b', '-u', '-t', '5', dc_ip],
            stderr=subprocess.STDOUT
        )
