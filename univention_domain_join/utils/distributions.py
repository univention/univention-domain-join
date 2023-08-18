#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

import subprocess


def get_distribution() -> str:
	return subprocess.check_output(['lsb_release', '-is']).strip().decode()


def get_release() -> str:
	return subprocess.check_output(['lsb_release', '-rs']).strip().decode()
