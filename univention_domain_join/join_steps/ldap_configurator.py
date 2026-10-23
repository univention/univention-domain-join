#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Create/update the machine's LDAP entry on the DC and configure OpenLDAP.

Creates (or updates) a UDM computer object of type computers/linux on the
DC — RPM distributions have no dedicated UDM type like Debian's
computers/ubuntu — and writes the local OpenLDAP client configuration.
On RPM based distributions that is /etc/openldap/ldap.conf instead of
Debian's /etc/ldap/ldap.conf.
"""

import os
import stat
import subprocess
from logging import getLogger
from shutil import copyfile

from univention_domain_join.join_steps.root_certificate_provider import RootCertificateProvider
from univention_domain_join.utils.distributions import get_distribution, get_release
from univention_domain_join.utils.general import execute_as_root, ssh
from univention_domain_join.utils.ldap import PW, UDM_CREATE_TYPE, get_machines_udm

userinfo_logger = getLogger('userinfo')
log = getLogger("debugging")

# OpenLDAP's client config lives in /etc/openldap on RPM based distributions
# (Debian/Ubuntu use /etc/ldap/ldap.conf instead).
LDAP_CONF = '/etc/openldap/ldap.conf'


class LdapConfigutationException(Exception):
    """Raised when the machine's LDAP entry cannot be created or updated."""


class ConflictChecker(object):
    """Detects pre-existing configuration that this step would overwrite."""

    def ldap_conf_exists(self) -> bool:
        """Return True (and warn) if the OpenLDAP client config already exists."""
        if os.path.isfile(LDAP_CONF):
            userinfo_logger.warn('Warning: %s already exists.' % LDAP_CONF)
            return True
        return False


class LdapConfigurator(ConflictChecker):
    """Creates the machine account on the DC and the local OpenLDAP config."""

    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        """Back up an existing OpenLDAP client config."""
        if self.ldap_conf_exists():
            os.makedirs(os.path.join(backup_dir, 'etc/openldap'), exist_ok=True)
            copyfile(
                LDAP_CONF,
                os.path.join(backup_dir, 'etc/openldap/ldap.conf')
            )

    def configure_ldap(self, dc_ip: str, ldap_server_name: str, admin_username: str, admin_pw: str, ldap_base: str, admin_dn: str) -> None:
        """Run the full LDAP step: root CA, machine account, ldap.conf, machine.secret."""
        RootCertificateProvider().provide_ucs_root_certififcate(dc_ip)
        password = self.random_password()
        self.modify_old_entry_or_add_machine_to_ldap(password, dc_ip, admin_username, admin_pw, ldap_base, admin_dn)
        self.create_ldap_conf_file(ldap_server_name, ldap_base)
        self.create_machine_secret_file(password)

    def modify_old_entry_or_add_machine_to_ldap(self, password: str, dc_ip: str, admin_username: str, admin_pw: str, ldap_base: str, admin_dn: str) -> str:
        """Update the machine's existing UDM entry or create a new one; returns its DN."""
        try:
            udm_type, dn = get_machines_udm(dc_ip, admin_username, admin_pw, admin_dn)
            log.info("Found existing LDAP entry %r of type %r", dn, udm_type)
        except LookupError:
            dn = self.add_machine_to_ldap(password, dc_ip, admin_username, admin_pw, ldap_base, admin_dn)
            log.info("Created LDAP entry %r", dn)
        else:
            self.modify_machine_in_ldap(password, dc_ip, admin_username, admin_pw, admin_dn, udm_type, dn)
            log.info("Modified LDAP entry %r", dn)
        return dn

    def modify_machine_in_ldap(self, password: str, dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str, udm_type: str, dn: str) -> None:
        """Set a new machine password and the OS info on an existing UDM entry."""
        userinfo_logger.info('Updating old LDAP entry for this machine on the UCS DC')

        release_id = get_distribution()
        release = get_release()

        cmd = [
            '/usr/sbin/udm',
            udm_type,
            'modify',
            '--binddn', admin_dn,
            '--bindpwdfile', PW(admin_username),
            '--dn', dn,
            '--set', 'password=%s' % (password,),
            '--set', 'operatingSystem=%s' % (release_id,),
            '--set', 'operatingSystemVersion=%s' % (release,)
        ]
        ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        _, stderr = ssh_process.communicate()
        if ssh_process.returncode != 0:
            userinfo_logger.critical('Updating the old LDAP entry for this computer failed.')
            log.critical("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
            raise LdapConfigutationException()

    def add_machine_to_ldap(self, password: str, dc_ip: str, admin_username: str, admin_pw: str, ldap_base: str, admin_dn: str) -> str:
        """Create a UDM computer object (computers/linux) for this machine; returns its DN."""
        userinfo_logger.info('Adding LDAP entry for this machine on the UCS DC')
        hostname = subprocess.check_output(['hostname', '-s']).strip().decode()
        release_id = get_distribution()
        release = get_release()
        # TODO: Also add MAC address. Which NIC's address should be used?
        udm_command = [
            '/usr/sbin/udm', UDM_CREATE_TYPE, 'create',
            '--binddn', admin_dn,
            '--bindpwdfile', PW(admin_username),
            '--position', 'cn=computers,%s' % (ldap_base,),
            '--set', 'name=%s' % (hostname,),
            '--set', 'password=%s' % (password,),
            '--set', 'operatingSystem=%s' % (release_id,),
            '--set', 'operatingSystemVersion=%s' % (release,)
        ]
        ssh_process = ssh(admin_username, admin_pw, dc_ip, udm_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ssh_process.communicate()
        if ssh_process.returncode != 0 or stderr.decode().startswith('E: '):
            userinfo_logger.critical('Adding an LDAP object for this computer didn\'t work.')
            userinfo_logger.critical(stderr.decode())
            raise LdapConfigutationException()
        prefix, _, dn = stdout.decode().strip().partition(": ")
        assert prefix == "Object created"
        return dn

    def get_admin_dn(self, dc_ip: str, admin_username: str, admin_pw: str, ldap_base: str) -> str:
        """Return the LDAP DN of the domain admin, via GSSAPI ldapwhoami on the DC.

        Uses the Kerberos ticket obtained by ldap.authenticate_admin().
        """
        userinfo_logger.info('Getting the DN of the Administrator ')
        ldap_command = ['ldapwhoami', '-QY', 'GSSAPI']
        ssh_process = ssh(admin_username, admin_pw, dc_ip, ldap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ssh_process.communicate()
        if ssh_process.returncode != 0:
            userinfo_logger.critical('get admin DN failed with: {}'.format(stderr.decode()))
            raise LdapConfigutationException('get admin DN failed with: {}'.format(stderr.decode()))
        dn, _, admin_dn = stdout.decode().strip().partition(':')
        assert dn == "dn", stdout
        return admin_dn

    @execute_as_root
    def create_ldap_conf_file(self, ldap_server_name: str, ldap_base: str) -> None:
        """Write the OpenLDAP client config pointing at the UCS DC (port 7389)."""
        userinfo_logger.info('Writing %s ' % LDAP_CONF)
        ldap_conf = \
            "TLS_CACERT /etc/univention/ssl/ucsCA/CAcert.pem\n" \
            "URI ldap://%s:7389\n" \
            "BASE %s\n" % (ldap_server_name, ldap_base)

        os.makedirs(os.path.dirname(LDAP_CONF), exist_ok=True)
        with open(LDAP_CONF, 'w') as conf_file:
            conf_file.write(ldap_conf)

    @execute_as_root
    def create_machine_secret_file(self, password: str) -> None:
        """Write the machine account password to /etc/machine.secret (read-only, root).

        sssd uses it to bind to the UCS LDAP as this machine.
        """
        userinfo_logger.info('Writing /etc/machine.secret ')
        with open('/etc/machine.secret', 'w') as secret_file:
            secret_file.write(password)
        os.chmod('/etc/machine.secret', stat.S_IREAD)

    def random_password(self, length: int = 20) -> str:
        """Generate a random password for the machine account."""
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[]^_`{|}~'
        password = ''
        for _ in range(length):
            password += chars[ord(os.urandom(1)) % len(chars)]
        return password
