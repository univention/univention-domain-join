#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2025 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only
"""General helpers: privilege handling, name resolution and SSH access to the DC."""

import os
import shlex
import socket
import subprocess
from functools import wraps
from typing import Any, Callable, List, TypeVar, Union, cast

F = TypeVar('F', bound=Callable[..., Any])


def execute_as_root(func: F) -> F:
    """Decorator that temporarily switches to uid 0 for the wrapped call.

    The CLI drops to the invoking user's uid (SUDO_UID) early on, so that
    e.g. downloads land in the right home; steps that write to /etc use
    this decorator to regain root privileges for a single call.
    """
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
    """Return True if the given host name can be resolved via DNS."""
    try:
        return bool(socket.getaddrinfo(name, 22, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP))
    except Exception:
        return False


def ssh(username: str, password: str, hostname: str, command: Union[str, List[str]], **kwargs: Any) -> subprocess.Popen:
    """Run a command on the DC over SSH, authenticating with a password via sshpass.

    The password is passed through the SSHPASS environment variable so it
    never appears on the command line. Host key checking is disabled
    because a joining client typically sees the DC for the first time.
    Extra keyword arguments are forwarded to subprocess.Popen.
    """
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
        command if isinstance(command, str) else " ".join(shlex.quote(arg) for arg in command),
    ]
    env = dict(kwargs.pop("env", os.environ), SSHPASS=password)
    proc = subprocess.Popen(cmd, env=env, **kwargs)
    return proc
