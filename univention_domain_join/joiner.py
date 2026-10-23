#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Orchestration of the domain join.

The Joiner runs the individual join steps (DNS, LDAP, SSSD, PAM, login
manager, Kerberos) in the right order and takes care of the backup of all
configuration files before anything is modified.
"""

import logging
import os
import time
from typing import Dict

from univention_domain_join.join_steps.dns_configurator import DnsConfigurator
from univention_domain_join.join_steps.dns_record_registrar import DnsRecordRegistrar
from univention_domain_join.join_steps.kerberos_configurator import KerberosConfigurator
from univention_domain_join.join_steps.ldap_configurator import LdapConfigurator
from univention_domain_join.join_steps.login_manager_configurator import LoginManagerConfigurator
from univention_domain_join.join_steps.pam_configurator import PamConfigurator
from univention_domain_join.join_steps.sssd_configurator import SssdConfigurator
from univention_domain_join.join_steps.sudoers_configurator import SudoersConfigurator
from univention_domain_join.utils import ldap
from univention_domain_join.utils.general import execute_as_root, name_is_resolvable

userinfo_logger = logging.getLogger('userinfo')


class DomainJoinException(Exception):
    """Raised when a pre-join check finds a problem that makes joining unsafe."""


class DcResolveException(Exception):
    """Raised when the UCS master or DC host names cannot be resolved via DNS."""


class Joiner(object):
    """Runs the domain join steps in order against a given UCS DC.

    Holds everything the join steps need, derived from the UCR variables
    fetched from the DC (domain name, nameservers, LDAP master/base/server
    name, Kerberos realm) plus the CLI credentials and options.
    """

    def __init__(self, ucr_variables: Dict[str, str], admin_username: str, admin_pw: str, dc_ip: str, skip_login_manager: bool, force_ucs_dns: bool, register_dns: bool = False, sudo_groups: list = None, sudo_groups_nopasswd: list = None) -> None:
        self.admin_username = admin_username
        self.admin_pw = admin_pw
        self.dc_ip = dc_ip
        self.skip_login_manager = skip_login_manager
        self.force_ucs_dns = force_ucs_dns
        self.register_dns = register_dns
        self.sudo_groups = sudo_groups or []
        self.sudo_groups_nopasswd = sudo_groups_nopasswd or []
        self.domain = ucr_variables['domainname']
        self.nameservers = [
            ucr_variables['nameserver1'] if ucr_variables['nameserver1'] != "''" else '',
            ucr_variables['nameserver2'] if ucr_variables['nameserver2'] != "''" else '',
            ucr_variables['nameserver3'] if ucr_variables['nameserver3'] != "''" else ''
        ]
        self.ldap_master = ucr_variables['ldap_master']
        self.ldap_base = ucr_variables['ldap_base']
        self.ldap_server_name = ucr_variables['ldap_server_name']
        self.kerberos_realm = ucr_variables['kerberos_realm']

    def check_if_join_is_possible_without_problems(self) -> None:
        """Abort the join if a conflicting login manager configuration is found."""
        if not self.skip_login_manager and LoginManagerConfigurator().configuration_conflicts():
            userinfo_logger.critical(
                'Joining the UCS domain is not safely possible.\n'
                'Please resolve all problems and run this tool again.'
            )
            raise DomainJoinException()

    def create_backup_of_config_files(self) -> None:
        """Back up every config file the join steps may modify.

        All backups go into /var/univention-backup/<timestamp>_domain-join/.
        """
        backup_dir = self.create_backup_dir()
        if self.force_ucs_dns:
            DnsConfigurator(self.nameservers, self.domain).backup(backup_dir)
        LdapConfigurator().backup(backup_dir)
        SssdConfigurator().backup(backup_dir)
        PamConfigurator().backup(backup_dir)
        if not self.skip_login_manager:
            LoginManagerConfigurator().backup(backup_dir)
        KerberosConfigurator().backup(backup_dir)
        if self.sudo_groups or self.sudo_groups_nopasswd:
            SudoersConfigurator(self.sudo_groups, self.sudo_groups_nopasswd).backup(backup_dir)
        userinfo_logger.info('Created a backup of all configuration files, that will be modified at \'%s\'.' % backup_dir)

    @execute_as_root
    def create_backup_dir(self) -> str:
        """Create and return the timestamped backup directory."""
        backup_dir = os.path.join('/var/univention-backup', time.strftime("%Y%m%d%H%M%S_domain-join", time.gmtime()))
        os.makedirs(backup_dir)
        return backup_dir

    def join_domain(self) -> None:
        """Perform the actual join: LDAP entry, SSSD, PAM, login manager, Kerberos.

        Optionally reconfigures DNS first (--force-ucs-dns). The temporary
        admin password file on the DC is always removed afterwards, even on
        failure.
        """
        try:
            if self.force_ucs_dns:
                userinfo_logger.info('changing network/dns configuration as requested.')
                DnsConfigurator(self.nameservers, self.domain).configure_dns()
            # check if we can resolve the ldap_server_name and ldap_master
            if not name_is_resolvable(self.ldap_master):
                raise DcResolveException('The UCS master name %s can not be resolved, please check your DNS settings' % self.ldap_master)
            if not name_is_resolvable(self.ldap_server_name):
                raise DcResolveException('The UCS DC name %s can not be resolved, please check your DNS settings' % self.ldap_server_name)
            ldap.authenticate_admin(self.dc_ip, self.admin_username, self.admin_pw)
            admin_dn = LdapConfigurator().get_admin_dn(self.dc_ip, self.admin_username, self.admin_pw, self.ldap_base)
            is_samba_dc = ldap.is_samba_dc(self.admin_username, self.admin_pw, self.dc_ip, admin_dn)
            LdapConfigurator().configure_ldap(self.dc_ip, self.ldap_server_name, self.admin_username, self.admin_pw, self.ldap_base, admin_dn)
            if self.register_dns:
                DnsRecordRegistrar().register_dns(self.dc_ip, self.admin_username, self.admin_pw, self.ldap_base, admin_dn, self.domain)
            SssdConfigurator().setup_sssd(self.dc_ip, self.ldap_master, self.ldap_server_name, self.admin_username, self.admin_pw, self.ldap_base, self.kerberos_realm, admin_dn, is_samba_dc)
            PamConfigurator().setup_pam()
            if self.sudo_groups or self.sudo_groups_nopasswd:
                SudoersConfigurator(self.sudo_groups, self.sudo_groups_nopasswd).setup_sudoers()
            if not self.skip_login_manager:
                LoginManagerConfigurator().enable_login_with_foreign_usernames()
            KerberosConfigurator().configure_kerberos(self.kerberos_realm, self.ldap_master, self.ldap_server_name, is_samba_dc, self.dc_ip)
            # TODO: Stop avahi service to prevent problems with sssd?
            userinfo_logger.info('The domain join was successful.')
            userinfo_logger.info('Please reboot the system.')
        finally:
            ldap.cleanup_authentication(self.dc_ip, self.admin_username, self.admin_pw)
