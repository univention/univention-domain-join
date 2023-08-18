#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

import subprocess
from logging import getLogger
from socket import gethostname
from typing import Tuple

from ldap.filter import filter_format

from univention_domain_join.utils.general import ssh

PW = "/dev/shm/{}domain-join".format
log = getLogger('debugging')


def authenticate_admin(dc_ip: str, admin_username: str, admin_pw: str) -> None:
    cmd = ['sh', '-e', '-u', '-c', 'cat >"$0"; chmod 600 "$0"; kinit --password-file="$0"', PW(admin_username)]
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    _, stderr = ssh_process.communicate(admin_pw.encode())
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())


def cleanup_authentication(dc_ip: str, admin_username: str, admin_pw: str) -> None:
    cmd = ['rm', '-f', PW(admin_username)]
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    _, stderr = ssh_process.communicate()
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())


def is_samba_dc(admin_username: str, admin_pw: str, dc_ip: str, admin_dn: str) -> bool:
    cmd = ['ldapsearch', '-QLLL', filter_format('(&(aRecord=%s)(univentionService=Samba 4))', [dc_ip]), '1.1']
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = ssh_process.communicate()
    if ssh_process.returncode or stderr:
        log.debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
    return bool(stdout.lstrip())


def get_machines_udm(dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str) -> Tuple[str, str]:
    for udm_type in ['computers/ubuntu', 'computers/linux', 'computers/ucc']:
        try:
            dn = get_machines_ldap_dn_given_the_udm_type(udm_type, dc_ip, admin_username, admin_pw, admin_dn)
            return (udm_type, dn)
        except LookupError:
            pass
    raise LookupError(dc_ip)


def get_machines_ldap_dn_given_the_udm_type(udm_type: str, dc_ip: str, admin_username: str, admin_pw: str, admin_dn: str) -> str:
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
