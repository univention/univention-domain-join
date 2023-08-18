#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

import os
import socket
import subprocess
from functools import wraps
from pipes import quote
from typing import Any, Callable, List, TypeVar, Union, cast

F = TypeVar('F', bound=Callable[..., Any])


def execute_as_root(func: F) -> F:
    @wraps(func)
    def root_wrapper(*args: Any, **kwargs: Any) -> Any:
        (ruid, euid, suid) = os.getresuid()
        os.setresuid(0, 0, suid)
        try:
            return_value = func(*args, **kwargs)
        finally:
            os.setresuid(ruid, euid, suid)
        return return_value
    return cast(F, root_wrapper)


def name_is_resolvable(name: str) -> bool:
    try:
        return bool(socket.getaddrinfo(name, 22, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP))
    except Exception:
        return False


def ssh(username: str, password: str, hostname: str, command: Union[str, List[str]], **kwargs: Any) -> subprocess.Popen:
    cmd = [
        "sshpass",
        "-e",  # Password is passed as env-var "SSHPASS"
        "ssh",
        "-F", "none",
        # "-o", "BatchMode=yes",  # conflicts with `sshpass`
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-l", username,
        hostname,
        command if isinstance(command, str) else " ".join(quote(arg) for arg in command),
    ]
    env = dict(kwargs.pop("env", os.environ), SSHPASS=password)
    proc = subprocess.Popen(cmd, env=env, **kwargs)
    return proc
