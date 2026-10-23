#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Configure PAM for domain logins via authselect.

This is the RPM replacement for Debian's pam-auth-update and
/usr/share/pam-configs: a custom authselect profile 'ucs' is created as a
copy of the stock sssd profile, extended with pam_group (for local group
memberships from /etc/security/group.conf) and selected with the
with-mkhomedir feature, so domain users get a home directory at first
login. On old distributions without authselect, authconfig is used as a
fallback.
"""

import grp
import logging
import os
import shutil
import subprocess
from shutil import copyfile

from univention_domain_join.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

GROUP_CONF = '/etc/security/group.conf'
# Name of the custom authselect profile this tool creates and selects.
AUTHSELECT_PROFILE = 'ucs'
AUTHSELECT_PROFILE_DIR = '/etc/authselect/custom/%s' % (AUTHSELECT_PROFILE,)
# Groups the domain users should become members of at login time, via
# pam_group. Groups that don't exist on the local system are skipped.
GROUPS_FOR_DOMAIN_USERS = ['audio', 'cdrom', 'dialout', 'floppy', 'adm', 'video']


class PamConfigurationException(Exception):
    """Raised when no supported PAM configuration tool (authselect/authconfig) exists."""


class ConflictChecker(object):
    """Detects pre-existing configuration that this step would overwrite."""

    def authselect_profile_exists(self) -> bool:
        """Return True (and warn) if the custom authselect profile already exists."""
        if os.path.isdir(AUTHSELECT_PROFILE_DIR):
            userinfo_logger.warn('Warning: %s already exists.' % AUTHSELECT_PROFILE_DIR)
            return True
        return False


class PamConfigurator(ConflictChecker):
    """Configures PAM/NSS for domain logins via authselect (or authconfig)."""

    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        """Back up group.conf, nsswitch.conf and the PAM files authselect rewrites."""
        if os.path.isfile(GROUP_CONF):
            os.makedirs(os.path.join(backup_dir, 'etc/security'), exist_ok=True)
            copyfile(GROUP_CONF, os.path.join(backup_dir, 'etc/security/group.conf'))
        if os.path.isfile('/etc/nsswitch.conf'):
            os.makedirs(os.path.join(backup_dir, 'etc'), exist_ok=True)
            copyfile('/etc/nsswitch.conf', os.path.join(backup_dir, 'etc/nsswitch.conf'))
        # authselect rewrites these files when a profile is selected.
        for pam_file in ('system-auth', 'password-auth'):
            path = os.path.join('/etc/pam.d', pam_file)
            if os.path.isfile(path) and not os.path.islink(path):
                os.makedirs(os.path.join(backup_dir, 'etc/pam.d'), exist_ok=True)
                copyfile(path, os.path.join(backup_dir, 'etc/pam.d', pam_file))

    def setup_pam(self) -> None:
        """Run the full PAM step: group memberships, authselect/authconfig, oddjobd."""
        self.add_users_to_required_system_groups()
        if shutil.which('authselect'):
            self.setup_authselect()
        elif shutil.which('authconfig'):
            self.setup_authconfig()
        else:
            userinfo_logger.critical('Neither authselect nor authconfig was found. Cannot configure PAM.')
            raise PamConfigurationException()
        self.enable_oddjobd()

    @execute_as_root
    def add_users_to_required_system_groups(self) -> None:
        """Append a pam_group rule to /etc/security/group.conf.

        Grants domain users membership in the usual local desktop groups
        (audio, video, ...) at login time; groups that don't exist locally
        are skipped.
        """
        groups = [g for g in GROUPS_FOR_DOMAIN_USERS if self.group_exists(g)]
        if not groups:
            return
        group_conf_line = '*;*;*;Al0000-2400;%s\n' % (','.join(groups),)
        if self.group_conf_already_ok(group_conf_line):
            return

        userinfo_logger.info('Adding groups to %s ' % GROUP_CONF)
        os.makedirs(os.path.dirname(GROUP_CONF), exist_ok=True)
        with open(GROUP_CONF, 'a') as groups_file:
            groups_file.write(group_conf_line)

    def group_exists(self, group: str) -> bool:
        """Return True if the given group exists on the local system."""
        try:
            grp.getgrnam(group)
            return True
        except KeyError:
            return False

    def group_conf_already_ok(self, group_conf_line: str) -> bool:
        """Return True if group.conf already contains this exact rule (idempotency)."""
        try:
            with open(GROUP_CONF, 'r') as groups_file:
                return group_conf_line in groups_file.read().splitlines(keepends=True)
        except IOError:
            return False

    @execute_as_root
    def setup_authselect(self) -> None:
        """Create the custom 'ucs' authselect profile and select it with-mkhomedir."""
        self.create_authselect_profile()
        self.add_pam_group_to_authselect_profile()

        userinfo_logger.info('Selecting the authselect profile custom/%s with-mkhomedir' % AUTHSELECT_PROFILE)
        subprocess.check_output(
            ['authselect', 'select', 'custom/%s' % (AUTHSELECT_PROFILE,), 'with-mkhomedir', '--force'],
            stderr=subprocess.STDOUT
        )

    @execute_as_root
    def create_authselect_profile(self) -> None:
        """Copy the stock sssd profile to /etc/authselect/custom/ucs (unless it exists)."""
        if os.path.isdir(AUTHSELECT_PROFILE_DIR):
            return
        userinfo_logger.info('Creating authselect profile %s based on the sssd profile' % AUTHSELECT_PROFILE)
        shutil.copytree('/usr/share/authselect/default/sssd', AUTHSELECT_PROFILE_DIR, symlinks=True)

    @execute_as_root
    def add_pam_group_to_authselect_profile(self) -> None:
        """Insert pam_group.so into the profile's system-auth/password-auth stacks.

        Needed so the group.conf rule actually takes effect; pam-auth-update
        did this via /usr/share/pam-configs on Debian/Ubuntu.
        """
        userinfo_logger.info('Adding pam_group to the authselect profile %s' % AUTHSELECT_PROFILE)
        for pam_file in ('system-auth', 'password-auth'):
            path = os.path.join(AUTHSELECT_PROFILE_DIR, pam_file)
            if not os.path.isfile(path):
                continue
            with open(path) as f:
                lines = f.readlines()
            if any('pam_group.so' in line for line in lines):
                continue
            pam_group_line = 'auth        required      pam_group.so use_first_pass\n'
            insert_at = next(
                (i for i, line in enumerate(lines)
                 if line.startswith('auth') and ('pam_unix.so' in line or 'pam_sss.so' in line)),
                len(lines)
            )
            lines.insert(insert_at, pam_group_line)
            with open(path, 'w') as f:
                f.writelines(lines)

    @execute_as_root
    def setup_authconfig(self) -> None:
        """Configure PAM via authconfig --update (sssd, sssdauth, mkhomedir)."""
        # Fallback for old distributions (RHEL 7 and alike) without authselect.
        userinfo_logger.info('Updating PAM via authconfig')
        subprocess.check_output(
            ['authconfig', '--enablesssd', '--enablesssdauth', '--enablemkhomedir', '--update'],
            stderr=subprocess.STDOUT
        )

    @execute_as_root
    def enable_oddjobd(self) -> None:
        """Enable and start oddjobd so pam_oddjob_mkhomedir can create home directories."""
        # authselect's with-mkhomedir feature uses pam_oddjob_mkhomedir,
        # which needs a running oddjobd to actually create home directories.
        userinfo_logger.info('Enabling oddjobd for automatic home directory creation')
        subprocess.check_output(
            ['systemctl', 'enable', '--now', 'oddjobd'],
            stderr=subprocess.STDOUT
        )
