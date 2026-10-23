#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Grants sudo rights to UCS domain groups via a sudoers drop-in.

The join options --sudo-groups and --sudo-groups-nopasswd write
/etc/sudoers.d/50-ucs-domain-groups with one rule per group. Groups given
with --sudo-groups must re-authenticate with their password (the safe
default); groups given with --sudo-groups-nopasswd get NOPASSWD rules,
which is intended for automation and lab use only. Domain groups resolve
through SSSD at runtime; spaces in group names are escaped as required by
the sudoers syntax. The drop-in is validated with visudo before it is put
in place — a broken sudoers would break sudo for everyone.
"""

import logging
import os
import stat
import subprocess
import tempfile
from shutil import copyfile
from typing import List, Optional

from univention_domain_join.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

SUDOERS_DROP_IN = '/etc/sudoers.d/50-ucs-domain-groups'


class SudoersConfigurationException(Exception):
    """Raised when the generated sudoers drop-in fails validation."""


class ConflictChecker(object):
    def sudoers_drop_in_exists(self) -> bool:
        if os.path.isfile(SUDOERS_DROP_IN):
            userinfo_logger.warn('Warning: %s already exists.' % SUDOERS_DROP_IN)
            return True
        return False


class SudoersConfigurator(ConflictChecker):
    """Writes and validates the sudoers drop-in for the given domain groups.

    sudo_groups get passworded rules, nopasswd_groups get NOPASSWD rules.
    """

    def __init__(self, sudo_groups: Optional[List[str]] = None, nopasswd_groups: Optional[List[str]] = None) -> None:
        self.sudo_groups = sudo_groups or []
        self.nopasswd_groups = nopasswd_groups or []

    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        if self.sudoers_drop_in_exists():
            os.makedirs(os.path.join(backup_dir, 'etc/sudoers.d'), exist_ok=True)
            copyfile(
                SUDOERS_DROP_IN,
                os.path.join(backup_dir, 'etc/sudoers.d/50-ucs-domain-groups')
            )

    def setup_sudoers(self) -> None:
        """Generate, validate and install the sudoers drop-in."""
        content = self.render_drop_in()
        self.validate(content)
        self.install(content)

    def render_drop_in(self) -> str:
        """One rule per group: %<group> ALL=(ALL:ALL) ALL for passworded
        groups, %<group> ALL=(ALL:ALL) NOPASSWD: ALL for nopasswd groups.
        Spaces in group names are escaped with a backslash, as required by
        sudoers."""
        lines = [
            '# Domain groups with sudo rights, created by univention-domain-join-cli.',
            '# Remove this file or re-run with --disjoin to revoke.',
        ]
        for group in self.sudo_groups:
            lines.append('%s ALL=(ALL:ALL) ALL' % self.escape_group_name(group))
        if self.nopasswd_groups:
            lines.append('# WARNING: passwordless sudo below — use for automation/lab groups only.')
        for group in self.nopasswd_groups:
            lines.append('%s ALL=(ALL:ALL) NOPASSWD: ALL' % self.escape_group_name(group))
        return '\n'.join(lines) + '\n'

    def escape_group_name(self, group: str) -> str:
        """Escape a group name for the sudoers syntax (% prefix, spaces escaped)."""
        return '%' + group.replace(' ', '\\ ')

    def validate(self, content: str) -> None:
        """Check the generated drop-in with visudo before installing it."""
        with tempfile.NamedTemporaryFile('w', suffix='.sudoers', delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            proc = subprocess.Popen(
                ['visudo', '-c', '-f', tmp_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            stdout, _ = proc.communicate()
            if proc.returncode != 0:
                userinfo_logger.critical('The generated sudoers configuration is invalid:\n%s' % stdout.decode())
                raise SudoersConfigurationException()
        finally:
            os.remove(tmp_path)

    @execute_as_root
    def install(self, content: str) -> None:
        userinfo_logger.info(
            'Writing %s for the domain groups: %s'
            % (SUDOERS_DROP_IN, ', '.join(self.sudo_groups + ['%s (nopasswd)' % g for g in self.nopasswd_groups]))
        )
        with open(SUDOERS_DROP_IN, 'w') as f:
            f.write(content)
        # sudoers.d files must be mode 0440, otherwise sudo ignores them.
        os.chmod(SUDOERS_DROP_IN, stat.S_IRUSR | stat.S_IRGRP)
