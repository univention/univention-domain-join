#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2022-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

from typing import Dict


class AbstractJoiner(object):
	def __init__(self, ucr_variables: Dict[str, str], admin_username: str, admin_pw: str, dc_ip: str, skip_login_manager: bool, force_ucs_dns: bool) -> None:
		raise NotImplementedError()

	def check_if_join_is_possible_without_problems(self) -> None:
		raise NotImplementedError()

	def create_backup_of_config_files(self) -> None:
		raise NotImplementedError()

	def join_domain(self) -> None:
		raise NotImplementedError()
