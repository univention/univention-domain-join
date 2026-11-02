#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Enable login with domain user names in the graphical login manager.

On RPM based distributions the active display manager is detected through
the display-manager.service systemd symlink (Debian/Ubuntu use
/etc/X11/default-display-manager instead). LightDM needs a drop-in config
to allow typing arbitrary (domain) user names; GDM and SDDM support that
out of the box.
"""

import logging
import os
from shutil import copyfile

from univention_domain_join.utils.general import execute_as_root

userinfo_logger = logging.getLogger('userinfo')

# On RPM based distributions the login manager is selected through the
# display-manager.service symlink (Debian/Ubuntu use
# /etc/X11/default-display-manager instead).
DISPLAY_MANAGER_SERVICE = '/etc/systemd/system/display-manager.service'


class ConflictChecker(object):
    """Detects login manager setups this tool cannot or already configured."""

    def configuration_conflicts(self) -> bool:
        """Return True if the system's display manager is unsupported.

        Headless systems (no display manager) and LightDM/GDM/SDDM are
        fine; anything else blocks the join unless --skip-login-manager is
        used.
        """
        login_manager = self.determine_used_login_manager()
        if login_manager is None:
            userinfo_logger.info('No display manager found (headless system?). Nothing to configure.')
            return False
        if login_manager in ('lightdm', 'gdm', 'gdm3', 'sddm'):
            return False
        userinfo_logger.error('Error: Can\'t enable login with the login manager of your system (%s).' % login_manager)
        userinfo_logger.error('       Please use LightDM, SDDM or GDM for full compatibility with UCS.')
        userinfo_logger.error('       This error can be avoided by using the --skip-login-manager parameter.')
        return True

    def determine_used_login_manager(self) -> str:
        """Return the display manager name from the display-manager.service symlink, or None."""
        if not os.path.exists(DISPLAY_MANAGER_SERVICE):
            return None
        return os.path.splitext(os.path.basename(os.path.realpath(DISPLAY_MANAGER_SERVICE)))[0]

    def lightdm_config_file_exists(self) -> bool:
        """Return True (and warn) if the LightDM drop-in this tool writes already exists."""
        if os.path.isfile('/etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf'):
            userinfo_logger.warn('Warning: /etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf already exists.')
            return True
        return False


class LoginManagerConfigurator(ConflictChecker):
    """Allows typing arbitrary (domain) user names at the graphical login."""

    @execute_as_root
    def backup(self, backup_dir: str) -> None:
        """Back up an existing LightDM drop-in config."""
        if self.lightdm_config_file_exists():
            os.makedirs(os.path.join(backup_dir, 'etc/lightdm/lightdm.conf.d'), exist_ok=True)
            copyfile(
                '/etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf',
                os.path.join(backup_dir, 'etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf')
            )

    def enable_login_with_foreign_usernames(self) -> None:
        """Enable manual user name entry; only LightDM needs a config change.

        GDM supports typing arbitrary user names through its
        "Not listed?" entry out of the box; SDDM accepts them in its
        user name field as well.
        """
        login_manager = self.determine_used_login_manager()
        if login_manager == 'lightdm':
            self.enable_login_with_foreign_usernames_for_lightdm()
        # GDM supports typing arbitrary user names through its
        # "Not listed?" entry out of the box; SDDM accepts them in its
        # user name field as well.

    @execute_as_root
    def enable_login_with_foreign_usernames_for_lightdm(self) -> None:
        """Write the LightDM drop-in that shows a manual login field and hides the user list."""
        userinfo_logger.info('Writing /etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf ')

        lightdm_config = \
            '[Seat:*]\n' \
            'greeter-show-manual-login=true\n' \
            'greeter-hide-users=true\n'

        os.makedirs('/etc/lightdm/lightdm.conf.d', exist_ok=True)
        with open('/etc/lightdm/lightdm.conf.d/99-show-manual-userlogin.conf', 'w') as conf_file:
            conf_file.write(lightdm_config)
