#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Command line interface of univention-domain-join-cli (RPM edition).

Parses the command line, runs pre-flight checks (root privileges,
supported distribution, required dependencies), discovers the UCS domain
and DC master, asks for domain administrator credentials, fetches the UCR
variables from the DC via SSH and then hands over to the Joiner, which
performs the actual join steps. With --disjoin it does the reverse:
the Disjoiner removes the computer object on the DC and cleans up the
local configuration.
"""

import argparse
import logging
import os
import shutil
import subprocess
import sys
from getpass import getpass
from logging import getLogger
from typing import Dict

from univention_domain_join import __version__
from univention_domain_join.joiner import Joiner
from univention_domain_join.utils.distributions import distribution_is_supported, get_distribution
from univention_domain_join.utils.domain import get_master_ip_through_dns, get_ucs_domainname
from univention_domain_join.utils.general import execute_as_root, ssh

# Commands that have to be present on the system. The value is the name of
# the RPM package that provides the command.
REQUIRED_COMMANDS = {
    'ssh': 'openssh-clients',
    'sshpass': 'sshpass',
    'ldapsearch': 'openldap-clients',
    'systemctl': 'systemd',
    'visudo': 'sudo',
}
REQUIRED_PYTHON_MODULES = {
    'dns': 'python3-dns',
    'ldap': 'python3-ldap',
}
# sssd provider modules and the RPM packages containing them. The base
# sssd package alone cannot serve id_provider=ldap / auth_provider=krb5.
SSSD_PROVIDERS = {
    'ldap': 'sssd-ldap',
    'krb5': 'sssd-krb5',
}
SSSD_PROVIDER_PATHS = ('/usr/lib64/sssd/libsss_%s.so', '/usr/lib/sssd/libsss_%s.so')


def check_if_run_as_root() -> None:
    """Exit unless the tool runs as root; all join steps need to write to /etc."""
    if os.getuid() != 0:
        print('This tool must be executed as root.')
        exit(1)


def check_distribution() -> None:
    """Exit unless /etc/os-release reports a supported RPM based distribution."""
    if not distribution_is_supported():
        getLogger("userinfo").critical(
            'The used distribution "%s" is not supported. This tool supports RPM based '
            'distributions (Fedora, RHEL, CentOS, Rocky, AlmaLinux, Oracle Linux).' % (get_distribution(),)
        )
        exit(1)


def check_dependencies() -> None:
    """Exit with a dnf install hint if required commands or Python modules are missing."""
    missing_packages = set(
        package for command, package in REQUIRED_COMMANDS.items() if not shutil.which(command)
    )
    missing_packages.update(
        package for module, package in REQUIRED_PYTHON_MODULES.items() if not module_available(module)
    )
    missing_packages.update(
        package
        for provider, package in SSSD_PROVIDERS.items()
        if not any(os.path.exists(path % provider) for path in SSSD_PROVIDER_PATHS)
    )
    if not (shutil.which('wget') or shutil.which('curl')):
        missing_packages.add('wget')
    if missing_packages:
        getLogger("userinfo").critical(
            'Missing dependencies. Please install them first:\n'
            '  dnf install %s' % (' '.join(sorted(missing_packages)),)
        )
        exit(1)


def module_available(module: str) -> bool:
    """Return True if the given Python module can be imported."""
    try:
        __import__(module)
        return True
    except ImportError:
        return False


@execute_as_root
def set_up_logging(logfile: str) -> None:
    """Configure the two loggers used throughout the tool.

    'userinfo' logs to stdout and the log file, 'debugging' logs command
    output and tracebacks to the log file only. Runs as root because the
    default log file lives in /var/log/univention.
    """
    verbose_formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
    plain_formatter = logging.Formatter('%(message)s')

    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    logfile_handler = logging.FileHandler(logfile)
    logfile_handler.setLevel(logging.DEBUG)
    logfile_handler.setFormatter(verbose_formatter)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.setFormatter(plain_formatter)

    userinfo_logger = logging.getLogger('userinfo')
    userinfo_logger.setLevel(logging.DEBUG)
    userinfo_logger.addHandler(logfile_handler)
    userinfo_logger.addHandler(stdout_handler)

    debugging_logger = logging.getLogger('debugging')
    debugging_logger.setLevel(logging.DEBUG)
    debugging_logger.addHandler(logfile_handler)


def get_admin_username() -> str:
    """Prompt interactively for the name of a domain administrator."""
    return input('Please enter the user name of a domain administrator: ')


def get_admin_password(admin_username: str) -> str:
    """Prompt interactively (without echo) for the administrator's password."""
    # TODO: Don't ask for the password if ssh works passwordless already.
    return getpass(prompt='Please enter the password for %s: ' % (admin_username,))


def check_if_ssh_works_with_given_account(dc_ip: str, admin_username: str, admin_pw: str) -> None:
    """Verify that SSH to the DC works with the given credentials; exit if not.

    Everything after this point (UCR fetch, UDM/LDAP operations) depends on
    working SSH access, so fail early with a clear message.
    """
    cmd = "true"
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    _, stderr = ssh_process.communicate()
    logging.getLogger('debugging').debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
    if ssh_process.returncode != 0:
        getLogger("userinfo").critical('It\'s not possible to connect to the UCS DC via ssh, with the given credentials.')
        exit(1)


def get_ucr_variables_from_dc(dc_ip: str, admin_username: str, admin_pw: str) -> Dict[str, str]:
    """Fetch all UCR variables from the DC via `ucr shell` over SSH.

    The 'hostname' variable is dropped because it is the DC's host name,
    not this client's.
    """
    cmd = "/usr/sbin/ucr shell"
    ssh_process = ssh(admin_username, admin_pw, dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert ssh_process.stdout
    ucr_variables = dict(
        line.decode("utf-8", "replace").strip().split("=", 1)
        for line in ssh_process.stdout
    )

    _, stderr = ssh_process.communicate()
    logging.getLogger('debugging').debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
    if ssh_process.wait() != 0:
        getLogger("userinfo").critical('Fetching the UCR variables from the UCS DC failed.')
        exit(1)

    ucr_variables.pop("hostname", None)
    return ucr_variables


def parse_args() -> argparse.Namespace:
    """Define and parse the command line arguments.

    Kept compatible with the Debian/Ubuntu version of the tool.
    """
    parser = argparse.ArgumentParser(
        description='Tool for joining an RPM based client computer into an UCS domain.'
    )
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('--username', help='User name of a domain administrator')
    parser.add_argument('--password', help='Password for the domain administrator')
    parser.add_argument('--password-file', help='Path to a file, containing the password for the domain administrator', metavar="FILE")
    parser.add_argument('--skip-login-manager', action='store_true', help='Do not configure the login manager')
    parser.add_argument('--domain', help='Domain name. Can be left out if the domain is configured for this system')
    parser.add_argument('--dc-ip', help='IP address of the UCS domain controller to join to. Can be used if --domain does not work. If unsure, use the IP of the UCS Master', metavar="IP")
    parser.add_argument('--force-ucs-dns', action='store_true', help='Change the system\'s DNS settings and set the UCS DC as DNS nameserver (default is to use the standard network settings, but make sure the your system can resolve the hostname of the UCS DC and the UCS master system)')
    parser.add_argument('--register-dns', action='store_true', help='Register a DNS record for this machine in the UCS DNS zone. Only done if the primary IP address of this machine is statically configured; DHCP clients are skipped')
    parser.add_argument('--sudo-groups', help='Comma-separated list of domain groups that get full sudo rights (password required), e.g. "Domain Admins,IT-Support"', metavar='GROUPS')
    parser.add_argument('--sudo-groups-nopasswd', help='Comma-separated list of domain groups that get passwordless sudo rights (NOPASSWD). Intended for automation/lab use only — prefer --sudo-groups for human admins', metavar='GROUPS')
    parser.add_argument('--disjoin', action='store_true', help='Leave the UCS domain: remove the computer object on the DC and clean up all local configuration created by the join')
    parser.add_argument('--local-only', action='store_true', help='With --disjoin: only clean up the local machine, do not remove the computer object on the DC (no credentials needed)')
    parser.add_argument('--yes', action='store_true', help='With --disjoin: do not ask for confirmation')
    parser.add_argument("--logfile", "-L", help="Path to log file %(default)s", metavar="FILE", default="/var/log/univention/domain-join-cli.log")
    args = parser.parse_args()
    return args


def resolve_dc_ip(args: argparse.Namespace) -> str:
    """Determine the IP of the DC master, from --dc-ip or via domain discovery."""
    if args.dc_ip:
        return args.dc_ip
    if not args.domain:
        args.domain = get_ucs_domainname()
        getLogger("userinfo").info('Automatically detected the domain %r.' % (args.domain))
    if not args.domain:
        getLogger("userinfo").critical(
            'Unable to determine the UCS domain automatically. Please provide '
            'it using the --domain parameter or use the tool with --dc-ip.'
        )
        exit(1)
    dc_ip = get_master_ip_through_dns(args.domain)
    if not dc_ip:
        getLogger("userinfo").critical(
            'No DNS record for the DC master could be found. Please make sure that '
            'the DC master is the DNS server for this computer or use this tool with --dc-ip.'
        )
        exit(1)
    return dc_ip


def get_admin_credentials(args: argparse.Namespace) -> tuple:
    """Return (username, password), from the arguments or interactively."""
    password = None
    if args.password:
        password = args.password
    elif args.password_file:
        try:
            with open(args.password_file) as password_file:
                password = password_file.read().strip()
        except IOError:
            getLogger("userinfo").error('Error: The password file could not be read.')
    if not args.username:
        args.username = get_admin_username()
    if not password:
        password = get_admin_password(args.username)
    return args.username, password


def disjoin(args: argparse.Namespace) -> None:
    """Leave the domain: remove the computer object on the DC and clean up locally."""
    from univention_domain_join.disjoiner import Disjoiner

    dc_ip = username = password = ldap_base = None
    if not args.local_only:
        dc_ip = resolve_dc_ip(args)
        username, password = get_admin_credentials(args)
        check_if_ssh_works_with_given_account(dc_ip, username, password)
        ucr_variables = get_ucr_variables_from_dc(dc_ip, username, password)
        ldap_base = ucr_variables['ldap_base']

    if not args.yes:
        answer = input(
            'This will remove this machine from the UCS domain%s. Continue? [y/N] '
            % ('' if args.local_only else ' (computer object on the DC will be deleted)')
        )
        if answer.lower() not in ('y', 'yes'):
            getLogger("userinfo").info('Aborted.')
            return

    Disjoiner(dc_ip, username, password, ldap_base, local_only=args.local_only, revert_dns=args.force_ucs_dns).disjoin()


def main() -> None:
    """Entry point: pre-flight checks, then join (default) or disjoin."""
    args = parse_args()

    check_if_run_as_root()
    ruid = int(os.environ.get('SUDO_UID', 0))
    if ruid:
        os.setresuid(ruid, ruid, 0)

    set_up_logging(args.logfile)
    check_distribution()
    check_dependencies()

    try:
        if args.disjoin:
            disjoin(args)
            return

        args.dc_ip = resolve_dc_ip(args)
        args.username, password = get_admin_credentials(args)
        check_if_ssh_works_with_given_account(args.dc_ip, args.username, password)
        ucr_variables = get_ucr_variables_from_dc(args.dc_ip, args.username, password)

        sudo_groups = [g.strip() for g in (args.sudo_groups or '').split(',') if g.strip()]
        sudo_groups_nopasswd = [g.strip() for g in (args.sudo_groups_nopasswd or '').split(',') if g.strip()]
        joiner = Joiner(ucr_variables, args.username, password, args.dc_ip, args.skip_login_manager, args.force_ucs_dns, register_dns=args.register_dns, sudo_groups=sudo_groups, sudo_groups_nopasswd=sudo_groups_nopasswd)
        joiner.check_if_join_is_possible_without_problems()
        joiner.create_backup_of_config_files()
        joiner.join_domain()
    except Exception as e:
        getLogger("userinfo").critical('An error occurred: %s. Please check %s for more information.' % (e, args.logfile))
        getLogger("debugging").critical(e, exc_info=True)
        exit(1)


if __name__ == '__main__':
    main()
