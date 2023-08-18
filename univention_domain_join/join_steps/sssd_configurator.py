#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

import logging
import os
import stat
import subprocess
from shutil import copyfile

from univention_domain_join.join_steps.root_certificate_provider import RootCertificateProvider
from univention_domain_join.utils.general import execute_as_root
from univention_domain_join.utils.ldap import get_machines_udm

userinfo_logger = logging.getLogger('userinfo')


class ConflictChecker(object):
    def sssd_conf_file_exists(self) -> bool:
        if os.path.isfile('/etc/sssd/sssd.conf'):
            userinfo_logger.warn('Warning: /etc/sssd/sssd.conf already exists.')
            return True
        return False


class SssdConfigurator(ConflictChecker):

    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        if self.sssd_conf_file_exists():
            os.makedirs(os.path.join(backup_dir, 'etc/sssd'), exist_ok=True)
            copyfile(
                '/etc/sssd/sssd.conf',
                os.path.join(backup_dir, 'etc/sssd/sssd.conf')
            )

    @execute_as_root
    def setup_sssd(self, dc_ip: str, ldap_master: str, ldap_server_name: str, admin_username: str, admin_pw: str, ldap_base: str, kerberos_realm: str, admin_dn: str, is_samba_dc: bool) -> None:
        self.ldap_password = open('/etc/machine.secret').read().strip()
        RootCertificateProvider().provide_ucs_root_certififcate(dc_ip)
        self.write_sssd_conf(dc_ip, ldap_master, ldap_server_name, admin_username, admin_pw, ldap_base, kerberos_realm, admin_dn, is_samba_dc)
        self.configure_sssd()
        self.restart_sssd()

    @execute_as_root
    def write_sssd_conf(self, dc_ip: str, ldap_master: str, ldap_server_name: str, admin_username: str, admin_pw: str, ldap_base: str, kerberos_realm: str, admin_dn: str, is_samba_dc: bool) -> None:
        userinfo_logger.info('Writing /etc/sssd/sssd.conf ')
        if is_samba_dc:
            kpasswd_server = ldap_server_name
        else:
            kpasswd_server = ldap_master
        sssd_conf = \
            '[sssd]\n' \
            'config_file_version = 2\n' \
            'reconnection_retries = 3\n' \
            'sbus_timeout = 30\n' \
            'services = nss, pam, sudo\n' \
            'domains = %(kerberos_realm)s\n' \
            '\n' \
            '[nss]\n' \
            'reconnection_retries = 3\n' \
            '\n' \
            '[pam]\n' \
            'reconnection_retries = 3\n' \
            '\n' \
            '[domain/%(kerberos_realm)s]\n' \
            'auth_provider = krb5\n' \
            'krb5_realm = %(kerberos_realm)s\n' \
            'krb5_server = %(ldap_server_name)s\n' \
            'krb5_kpasswd = %(kpasswd_server)s\n' \
            'id_provider = ldap\n' \
            'ldap_uri = ldap://%(ldap_server_name)s:7389\n' \
            'ldap_search_base = %(ldap_base)s\n' \
            'ldap_tls_reqcert = never\n' \
            'ldap_tls_cacert = /etc/univention/ssl/ucsCA/CAcert.pem\n' \
            'cache_credentials = true\n' \
            'enumerate = true\n' \
            'ldap_default_bind_dn = %(machines_ldap_dn)s\n' \
            'ldap_default_authtok_type = password\n' \
            'ldap_default_authtok = %(ldap_password)s\n' \
            % {
                'kerberos_realm': kerberos_realm,
                'kpasswd_server': kpasswd_server,
                'ldap_base': ldap_base,
                'ldap_server_name': ldap_server_name,
                'ldap_password': self.ldap_password,
                'machines_ldap_dn': get_machines_udm(dc_ip, admin_username, admin_pw, admin_dn)[1],
            }
        with open('/etc/sssd/sssd.conf', 'w') as conf_file:
            conf_file.write(sssd_conf)
        os.chmod('/etc/sssd/sssd.conf', stat.S_IREAD | stat.S_IWRITE)

    @execute_as_root
    def configure_sssd(self) -> None:
        userinfo_logger.info('Configuring auth config profile for sssd')

        subprocess.check_output(
            ['pam-auth-update', '--enable', 'mkhomedir'],
            stderr=subprocess.STDOUT
        )

    @execute_as_root
    def restart_sssd(self) -> None:
        userinfo_logger.info('Restarting sssd')

        subprocess.check_output(
            ['service', 'sssd', 'restart'],
            stderr=subprocess.STDOUT
        )
