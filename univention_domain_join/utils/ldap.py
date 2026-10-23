#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""UDM/LDAP operations on the UCS DC, all executed remotely over SSH.

The client has no local UDM installation, so every operation (udm,
ldapsearch, ldapwhoami, kinit) is run on the DC through the ssh() helper.
Authentication for those remote calls uses a temporary password file in
/dev/shm on the DC (tmpfs, so the password never hits a disk there).
"""

import subprocess
from logging import getLogger
from socket import gethostname
from typing import Tuple

from ldap.filter import filter_format

from univention_domain_join.utils.general import ssh

PW = "/dev/shm/{}domain-join".format
log = getLogger('debugging')

# UDM computer types to probe when looking for an existing entry of this
# machine. New entries are created as UDM_CREATE_TYPE.
UDM_LOOKUP_TYPES = ['computers/linux', 'computers/ucc', 'computers/ubuntu']
UDM_CREATE_TYPE = 'computers/linux'


def authenticate_admin(dc_ip: str, admin_username: str, admin_pw: str) -> None:
    """Store the admin password on the DC and kinit with it.

    Writes the password to a root-only file in /dev/shm on the DC and
    obtains a Kerberos ticket, so that later UDM/ldapsearch calls can
    authenticate via --bindpwdfile without the password on the command
    line. Pair with cleanup_authentication().
    """
    cmd = ['sh', '-e', '-u', '-c', 'cat >"$0"; chmod 600 "$0"; kinit --password-file="$0"', PW(admin_username)]
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    _, stderr = ssh_process.communicate(admin_pw.encode())
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())


def cleanup_authentication(dc_ip: str, admin_username: str, admin_pw: str) -> None:
    """Remove the temporary admin password file from the DC."""
    cmd = ['rm', '-f', PW(admin_username)]
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    _, stderr = ssh_process.communicate()
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())


def is_samba_dc(admin_username: str, admin_pw: str, dc_ip: str, admin_dn: str) -> bool:
    """Return True if the DC we are joining against runs the Samba 4 service.

    Samba DCs provide the kpasswd service themselves, so sssd.conf and
    krb5.conf must point kpasswd at the Samba DC instead of the master.
    """
    cmd = ['ldapsearch', '-QLLL', filter_format('(&(aRecord=%s)(univentionService=Samba 4))', [dc_ip]), '1.1']
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = ssh_process.communicate()
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
    return bool(stdout.lstrip())


def get_machines_udm(dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str) -> Tuple[str, str]:
    """Find this machine's existing UDM computer entry on the DC.

    Tries the UDM types in UDM_LOOKUP_TYPES and returns (udm_type, dn) of
    the first match. Raises LookupError if the machine has no entry yet;
    new entries are created as computers/linux, since RPM distributions
    have no dedicated UDM computer type.
    """
    for udm_type in UDM_LOOKUP_TYPES:
        try:
            dn = get_machines_ldap_dn_given_the_udm_type(udm_type, dc_ip, admin_username, admin_pw, admin_dn)
            return (udm_type, dn)
        except LookupError:
            pass
    raise LookupError(dc_ip)


def get_machines_ldap_dn_given_the_udm_type(udm_type: str, dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str) -> str:
    """Return the LDAP DN of this machine's UDM entry of the given type.

    Raises LookupError if no entry with this machine's (short) hostname
    exists for that UDM type.
    """
    hostname = gethostname()
    cmd = ['/usr/sbin/udm', udm_type, 'list', '--binddn', admin_dn, '--bindpwdfile', PW(admin_username), '--filter', 'name=%s' % (hostname,)]
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert ssh_process.stdout
    for line in ssh_process.stdout:
        key, _, val = line.decode().partition(': ')
        if key == "DN":
            return val.strip()
    _, stderr = ssh_process.communicate()
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
    raise LookupError(hostname)
