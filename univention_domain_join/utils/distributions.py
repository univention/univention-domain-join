#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""Distribution detection via /etc/os-release.

Replaces ``lsb_release`` from the Debian/Ubuntu version, which is not
available (or not installed by default) on RPM based distributions.
"""

from typing import Tuple

OS_RELEASE = '/etc/os-release'

# Distribution IDs (from /etc/os-release) this tool supports. All of them are
# RPM based and use dnf (or yum) plus authselect for PAM configuration.
SUPPORTED_DISTRIBUTIONS = (
    'fedora',
    'rhel',
    'centos',
    'rocky',
    'almalinux',
    'ol',        # Oracle Linux
    'amzn',      # Amazon Linux
)


def _os_release() -> dict:
    """Parse /etc/os-release into a dict; empty if the file is unreadable."""
    values = {}
    try:
        with open(OS_RELEASE) as f:
            for line in f:
                key, _, value = line.partition('=')
                values[key.strip()] = value.strip().strip('"')
    except IOError:
        pass
    return values


def get_distribution() -> str:
    """Human readable distribution name, e.g. 'Rocky Linux'."""
    return _os_release().get('NAME', 'unknown')


def get_distribution_id() -> str:
    """Machine readable distribution id, e.g. 'rocky'."""
    return _os_release().get('ID', 'unknown').lower()


def get_distribution_id_like() -> Tuple[str, ...]:
    """IDs of distributions this one is derived from (ID_LIKE), e.g. ('rhel', 'fedora')."""
    return tuple(_os_release().get('ID_LIKE', '').split())


def get_release() -> str:
    """Distribution release, e.g. '9.4'."""
    return _os_release().get('VERSION_ID', 'unknown')


def distribution_is_supported() -> bool:
    """Return True for known RPM distribution IDs or RHEL/Fedora derivatives."""
    dist_id = get_distribution_id()
    if dist_id in SUPPORTED_DISTRIBUTIONS:
        return True
    id_like = get_distribution_id_like()
    return 'rhel' in id_like or 'fedora' in id_like
