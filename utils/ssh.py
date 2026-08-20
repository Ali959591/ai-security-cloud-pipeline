"""SSH helpers for remote GPU job deployment."""

from pathlib import Path

from config import SSHConfig


def deploy_via_ssh(
    config: SSHConfig,
    *,
    command: str,
    dry_run: bool = False,
) -> int:
    """
    Start a remote run over SSH.

    Returns a process exit code (0 on success).
    """
    key = config.key_path or Path("~/.ssh/id_rsa").expanduser()
    target = f"{config.user}@{config.host}"

    if dry_run:
        print(f"[dry-run] ssh -p {config.port} -i {key} {target} 'cd {config.remote_workdir} && {command}'")
        return 0

    # TODO: wire up paramiko or subprocess ssh invocation
    raise NotImplementedError("SSH deploy is not implemented yet.")
