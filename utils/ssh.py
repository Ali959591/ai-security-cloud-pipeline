"""SSH helpers for remote GPU job deployment."""

from __future__ import annotations

import socket
import threading
from io import TextIOWrapper
from pathlib import Path
from typing import TYPE_CHECKING

import paramiko
from rich.console import Console

from config import SSHConfig

if TYPE_CHECKING:
    from paramiko.channel import ChannelFile


class SSHConnectionError(Exception):
    """Raised when an SSH connection or authentication step fails."""


def _load_private_key(key_path: Path) -> paramiko.PKey:
    key_loaders = (
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.RSAKey,
        paramiko.DSSKey,
    )
    for loader in key_loaders:
        try:
            return loader.from_private_key_file(str(key_path))
        except paramiko.SSHException:
            continue
    raise SSHConnectionError(f"Unable to load private key: {key_path}")


def _connect(
    host: str,
    port: int,
    username: str,
    *,
    key_path: Path | None = None,
    password: str | None = None,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict[str, object] = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 30,
        "allow_agent": password is None,
        "look_for_keys": key_path is None and password is None,
    }

    if key_path is not None:
        if not key_path.expanduser().is_file():
            raise SSHConnectionError(f"Key file not found: {key_path}")
        connect_kwargs["pkey"] = _load_private_key(key_path.expanduser())

    if password is not None:
        connect_kwargs["password"] = password

    try:
        client.connect(**connect_kwargs)
    except paramiko.AuthenticationException as exc:
        raise SSHConnectionError(f"Authentication failed for {username}@{host}:{port}") from exc
    except paramiko.SSHException as exc:
        raise SSHConnectionError(f"SSH error connecting to {host}:{port}: {exc}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise SSHConnectionError(f"Connection timed out reaching {host}:{port}") from exc
    except OSError as exc:
        raise SSHConnectionError(f"Could not reach {host}:{port}: {exc}") from exc

    return client


def _stream_pipe(pipe: ChannelFile | TextIOWrapper, console: Console, *, style: str | None = None) -> None:
    while True:
        chunk = pipe.read(4096)
        if not chunk:
            break
        text = chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else chunk
        console.print(text, end="", style=style)


def run_remote_command(
    host: str,
    port: int,
    username: str,
    command: str,
    *,
    key_path: Path | None = None,
    password: str | None = None,
    console: Console | None = None,
) -> int:
    """
    Connect over SSH and execute a bash command on the remote host.

    Streams stdout/stderr live to the console and returns the remote exit code.
    """
    out = console or Console()
    client: paramiko.SSHClient | None = None

    try:
        client = _connect(host, port, username, key_path=key_path, password=password)
        _, stdout, stderr = client.exec_command(f"bash -lc {paramiko.util.shell_quote(command)}")

        stdout_thread = threading.Thread(target=_stream_pipe, args=(stdout, out), daemon=True)
        stderr_thread = threading.Thread(
            target=_stream_pipe,
            args=(stderr, out),
            kwargs={"style": "red"},
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        stdout_thread.join()
        stderr_thread.join()

        return stdout.channel.recv_exit_status()
    except SSHConnectionError:
        raise
    except paramiko.SSHException as exc:
        raise SSHConnectionError(f"Remote command failed: {exc}") from exc
    finally:
        if client is not None:
            client.close()


def deploy_via_ssh(
    config: SSHConfig,
    *,
    command: str,
    dry_run: bool = False,
    password: str | None = None,
    console: Console | None = None,
) -> int:
    """
    Start a remote run over SSH.

    Returns a process exit code (0 on success).
    """
    key = config.key_path or Path("~/.ssh/id_rsa")
    target = f"{config.user}@{config.host}"
    remote_command = f"cd {config.remote_workdir} && {command}"
    out = console or Console()

    if dry_run:
        auth = f"-i {key.expanduser()}" if config.key_path or key.expanduser().is_file() else "[password]"
        out.print(f"[dim][dry-run][/] ssh -p {config.port} {auth} {target} {remote_command!r}")
        return 0

    return run_remote_command(
        config.host,
        config.port,
        config.user,
        remote_command,
        key_path=config.key_path,
        password=password,
        console=out,
    )
