#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Disjoin: leave the UCS domain and clean up the local configuration.

Reverses everything the join did:

- Deletes the machine's computer object on the DC via udm, unless
  --local-only was given. The DNS records attached to the computer object
  (dnsEntryZoneForward/dnsEntryZoneReverse, e.g. created by
  --register-dns) are separate LDAP objects under cn=dns and are deleted
  explicitly before the computer object is removed.
- Restores the configuration files that existed before the join from the
  newest backup in /var/univention-backup/<timestamp>_domain-join/ and
  deletes the files the join created (sssd.conf, krb5.conf, ldap.conf,
  machine.secret, the lightdm drop-in).
- Reverts PAM to the stock authselect sssd profile and removes the
  custom/ucs profile (or reverts via authconfig on old distributions).
- Removes the UCS root certificate from the system trust store.
- Stops and disables sssd.
- Optionally reverts the NetworkManager DNS settings (when --force-ucs-dns
  was used at join time, pass it again at disjoin time).
"""

import glob
import logging
import os
import shutil
import subprocess
from typing import Optional

from univention_domain_join.utils import ldap
from univention_domain_join.utils.general import execute_as_root, ssh
from univention_domain_join.utils.ldap import PW, get_machines_udm

userinfo_logger = logging.getLogger('userinfo')
log = logging.getLogger('debugging')

BACKUP_ROOT = '/var/univention-backup'

# Files that are restored from the join backup if they were backed up
# (i.e. they existed before the join), relative to the backup directory.
RESTORABLE_PATHS = [
    'etc/krb5.conf',
    'etc/openldap/ldap.conf',
    'etc/sssd/sssd.conf',
    'etc/security/group.conf',
    'etc/nsswitch.conf',
    'etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf',
    'etc/sudoers.d/50-ucs-domain-groups',
    'etc/resolv.conf',
]

# Files the join may have created: deleted on disjoin when there is no
# older version in the backup to restore.
JOIN_CREATED_PATHS = [
    '/etc/krb5.conf',
    '/etc/openldap/ldap.conf',
    '/etc/sssd/sssd.conf',
    '/etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf',
    '/etc/sudoers.d/50-ucs-domain-groups',
]

# Files the join always created; unconditionally deleted on disjoin.
JOIN_ARTIFACTS = [
    '/etc/machine.secret',
    '/etc/univention/ssl/ucsCA/CAcert.pem',
    '/etc/pki/ca-trust/source/anchors/UCSdomain.crt',
]

AUTHSELECT_PROFILE_DIR = '/etc/authselect/custom/ucs'


class DisjoinException(Exception):
    """Raised when the disjoin cannot be performed safely."""


class Disjoiner(object):
    """Removes this machine from the UCS domain and cleans up locally."""

    def __init__(self, dc_ip: Optional[str] = None, admin_username: Optional[str] = None, admin_pw: Optional[str] = None, ldap_base: Optional[str] = None, local_only: bool = False, revert_dns: bool = False) -> None:
        self.dc_ip = dc_ip
        self.admin_username = admin_username
        self.admin_pw = admin_pw
        self.ldap_base = ldap_base
        self.local_only = local_only
        self.revert_dns = revert_dns

    def disjoin(self) -> None:
        """Run the full disjoin: remove the computer object on the DC
        (unless local-only), then clean up the local configuration."""
        try:
            if not self.local_only:
                ldap.authenticate_admin(self.dc_ip, self.admin_username, self.admin_pw)
                admin_dn = self.get_admin_dn()
                self.remove_computer_object(admin_dn)
            self.cleanup_local_configuration()
            userinfo_logger.info('The domain disjoin was successful.')
            userinfo_logger.info('Please reboot the system.')
        finally:
            if not self.local_only:
                ldap.cleanup_authentication(self.dc_ip, self.admin_username, self.admin_pw)

    def get_admin_dn(self) -> str:
        """Resolve the DN of the admin account via GSSAPI on the DC."""
        cmd = ['ldapwhoami', '-QY', 'GSSAPI']
        ssh_process = ssh(self.admin_username, self.admin_pw, self.dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = ssh_process.communicate()
        if ssh_process.returncode != 0:
            userinfo_logger.critical('get admin DN failed with: %s' % stderr.decode())
            raise DisjoinException()
        dn, _, admin_dn = stdout.decode().strip().partition(':')
        assert dn == "dn", stdout
        return admin_dn

    def remove_computer_object(self, admin_dn: str) -> None:
        """Delete the machine's computer object on the DC via udm.

        The DNS records (dns/host_record, dns/ptr_record) are separate
        LDAP objects under cn=dns and are NOT removed together with the
        computer object — they are deleted explicitly first.
        """
        try:
            udm_type, dn = get_machines_udm(self.dc_ip, self.admin_username, self.admin_pw, admin_dn)
        except LookupError:
            userinfo_logger.warn('Warning: no computer object for this machine was found on the DC. Continuing with the local cleanup.')
            return
        for record_module, record_dn in self.get_dns_records_of_computer(udm_type, admin_dn):
            self.remove_dns_record(record_module, record_dn, admin_dn)
        userinfo_logger.info('Removing the computer object %s on the UCS DC' % dn)
        self.run_udm([
            '/usr/sbin/udm', udm_type, 'remove',
            '--binddn', admin_dn,
            '--bindpwdfile', PW(self.admin_username),
            '--dn', dn,
        ], 'removing the computer object on the DC')

    def get_dns_records_of_computer(self, udm_type: str, admin_dn: str) -> list:
        """Return the (udm module, dn) pairs of the DNS records attached to
        this machine's computer object, derived from its
        dnsEntryZoneForward/dnsEntryZoneReverse attributes."""
        hostname = subprocess.check_output(['hostname', '-s']).strip().decode()
        cmd = [
            '/usr/sbin/udm', udm_type, 'list',
            '--binddn', admin_dn,
            '--bindpwdfile', PW(self.admin_username),
            '--filter', 'name=%s' % (hostname,),
        ]
        ssh_process = ssh(self.admin_username, self.admin_pw, self.dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = ssh_process.communicate()
        records = []
        for line in stdout.decode().splitlines():
            key, _, value = line.partition(': ')
            key = key.strip()
            zone_dn, _, ip = value.strip().partition(' ')
            if not zone_dn:
                continue
            if key == 'dnsEntryZoneForward':
                records.append(('dns/host_record', 'relativeDomainName=%s,%s' % (hostname, zone_dn)))
            elif key == 'dnsEntryZoneReverse':
                records.append(('dns/ptr_record', 'relativeDomainName=%s,%s' % (ip.split('.')[-1], zone_dn)))
        return records

    def remove_dns_record(self, record_module: str, record_dn: str, admin_dn: str) -> None:
        """Delete a single DNS record object on the DC (best effort)."""
        userinfo_logger.info('Removing DNS record %s on the UCS DC' % record_dn)
        self.run_udm([
            '/usr/sbin/udm', record_module, 'remove',
            '--binddn', admin_dn,
            '--bindpwdfile', PW(self.admin_username),
            '--dn', record_dn,
        ], 'removing the DNS record %s' % record_dn)

    def run_udm(self, cmd: list, description: str) -> bool:
        """Run a udm command on the DC via SSH; warn (don't abort) on failure."""
        ssh_process = ssh(self.admin_username, self.admin_pw, self.dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = ssh_process.communicate()
        if ssh_process.returncode != 0 or stderr.decode().startswith('E: '):
            userinfo_logger.warn('Warning: %s failed (%s). Continuing with the local cleanup.' % (description, stderr.decode().strip()))
            log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
            return False
        return True

    def cleanup_local_configuration(self) -> None:
        """Undo all local changes of the join."""
        self.stop_sssd()
        self.revert_pam()
        self.restore_or_remove_config_files()
        self.remove_join_artifacts()
        self.remove_group_conf_entry()
        if self.revert_dns:
            self.revert_network_manager_dns()

    @execute_as_root
    def stop_sssd(self) -> None:
        """Stop and disable sssd; it is no longer usable without the domain."""
        if not shutil.which('systemctl'):
            return
        userinfo_logger.info('Stopping and disabling sssd')
        subprocess.call(['systemctl', 'disable', '--now', 'sssd'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @execute_as_root
    def revert_pam(self) -> None:
        """Switch PAM back to the stock sssd authselect profile (keeping
        mkhomedir for local users) and remove the custom/ucs profile.
        Falls back to authconfig on distributions without authselect."""
        if shutil.which('authselect'):
            userinfo_logger.info('Reverting PAM to the stock sssd authselect profile')
            subprocess.check_output(
                ['authselect', 'select', 'sssd', 'with-mkhomedir', '--force'],
                stderr=subprocess.STDOUT
            )
            if os.path.isdir(AUTHSELECT_PROFILE_DIR):
                shutil.rmtree(AUTHSELECT_PROFILE_DIR)
        elif shutil.which('authconfig'):
            userinfo_logger.info('Reverting PAM via authconfig')
            subprocess.check_output(
                ['authconfig', '--disablesssd', '--disablesssdauth', '--disablemkhomedir', '--update'],
                stderr=subprocess.STDOUT
            )

    def find_latest_backup(self) -> Optional[str]:
        """Return the newest join backup directory, or None if there is none."""
        backups = sorted(glob.glob(os.path.join(BACKUP_ROOT, '*_domain-join')))
        return backups[-1] if backups else None

    @execute_as_root
    def restore_or_remove_config_files(self) -> None:
        """Restore every file that was backed up during the join; delete
        join-created config files that have no pre-join version.

        shutil.copy2 must not be used here: it copies extended attributes,
        including the security.selinux xattr, so files restored from
        /var/univention-backup would keep the var_t label and become
        unreadable for confined services like sssd (SELinux EACCES).
        copyfile+copymode copy content and permission bits only, and
        restorecon fixes the label in case the target already existed
        with a wrong one."""
        backup_dir = self.find_latest_backup()
        if backup_dir:
            userinfo_logger.info('Restoring configuration files from the join backup %s' % backup_dir)
            for relpath in RESTORABLE_PATHS:
                source = os.path.join(backup_dir, relpath)
                target = os.path.join('/', relpath)
                if os.path.isfile(source):
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    shutil.copyfile(source, target)
                    shutil.copymode(source, target)
                    self.fix_selinux_label(target)
                    userinfo_logger.info('Restored %s' % target)
        else:
            userinfo_logger.info('No join backup found in %s; join-created files will be deleted.' % BACKUP_ROOT)

        backup_dir = backup_dir or ''
        for path in JOIN_CREATED_PATHS:
            if os.path.isfile(path) and not os.path.isfile(os.path.join(backup_dir, path[1:])):
                userinfo_logger.info('Removing %s (created by the join, no pre-join version exists)' % path)
                os.remove(path)

    def fix_selinux_label(self, path: str) -> None:
        """Restore the default SELinux label of a restored file, if
        SELinux tooling is present. A no-op on systems without it."""
        if shutil.which('restorecon'):
            subprocess.call(['restorecon', path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @execute_as_root
    def remove_join_artifacts(self) -> None:
        """Delete the machine password, the UCS root certificate and the
        trust store anchor, then rebuild the trust store."""
        for path in JOIN_ARTIFACTS:
            if os.path.isfile(path):
                userinfo_logger.info('Removing %s' % path)
                os.remove(path)
        if os.path.isdir('/etc/univention/ssl/ucsCA'):
            os.rmdir('/etc/univention/ssl/ucsCA')
        if shutil.which('update-ca-trust'):
            subprocess.check_output(['update-ca-trust', 'extract'], stderr=subprocess.STDOUT)

    @execute_as_root
    def remove_group_conf_entry(self) -> None:
        """Remove the pam_group line the join added to
        /etc/security/group.conf, if that file was not restored from a
        backup (in which case the line is already gone)."""
        group_conf = '/etc/security/group.conf'
        if not os.path.isfile(group_conf):
            return
        with open(group_conf) as f:
            lines = f.readlines()
        kept = [line for line in lines if not line.startswith('*;*;*;Al0000-2400;')]
        if len(kept) != len(lines):
            userinfo_logger.info('Removing the domain groups entry from %s' % group_conf)
            with open(group_conf, 'w') as f:
                f.writelines(kept)

    @execute_as_root
    def revert_network_manager_dns(self) -> None:
        """Revert the NetworkManager DNS settings made by --force-ucs-dns:
        hand DNS back to DHCP on every active connection."""
        if not shutil.which('nmcli'):
            return
        p = subprocess.Popen(
            ['nmcli', '-t', '-f', 'NAME,UUID,DEVICE', 'connection', 'show', '--active'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = p.communicate()
        if p.returncode != 0:
            return
        for line in stdout.decode().splitlines():
            _, conn_uuid, conn_dev = line.rsplit(':', 2)
            userinfo_logger.info('Reverting DNS settings of %s to automatic' % conn_dev)
            subprocess.call([
                'nmcli', 'connection', 'modify', conn_uuid,
                'ipv4.dns', '',
                'ipv4.ignore-auto-dns', 'no',
                'ipv4.dns-search', ''
            ])
            subprocess.call(['nmcli', 'connection', 'down', conn_uuid])
            subprocess.call(['nmcli', 'connection', 'up', conn_uuid])
