"""AI Security and Remote Cloud CLI."""

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import AppConfig, GPUConfig, SecurityConfig, SSHConfig, load_config
from utils.gpu import check_gpu_usage
from utils.security import scan_prompt
from utils.ssh import deploy_via_ssh

app = typer.Typer(
    name="ai-security-cloud",
    help="Deploy remote GPU workloads, monitor usage, and scan prompts for injection attacks.",
    no_args_is_help=True,
)
console = Console()


def _cfg() -> AppConfig:
    return load_config()


@app.command("deploy-gpu")
def deploy_gpu(
    command: Annotated[str, typer.Argument(help="Remote shell command to execute on the GPU host.")],
    host: Annotated[Optional[str], typer.Option(help="SSH host override.")] = None,
    port: Annotated[Optional[int], typer.Option(help="SSH port override.")] = None,
    user: Annotated[Optional[str], typer.Option(help="SSH user override.")] = None,
    key: Annotated[Optional[Path], typer.Option(help="Path to SSH private key.")] = None,
    workdir: Annotated[Optional[str], typer.Option(help="Remote working directory.")] = None,
    dry_run: Annotated[bool, typer.Option(help="Print the SSH command without executing.")] = False,
) -> None:
    """Start an SSH session and launch a remote GPU run."""
    cfg = _cfg()
    ssh = SSHConfig(
        host=host or cfg.ssh.host,
        port=port or cfg.ssh.port,
        user=user or cfg.ssh.user,
        key_path=key or cfg.ssh.key_path,
        remote_workdir=workdir or cfg.ssh.remote_workdir,
    )

    console.print(Panel.fit(f"[bold cyan]Deploy GPU[/] -> {ssh.user}@{ssh.host}:{ssh.port}", border_style="cyan"))

    try:
        exit_code = deploy_via_ssh(ssh, command=command, dry_run=dry_run)
    except NotImplementedError as exc:
        console.print(f"[yellow]Stub:[/] {exc}")
        raise typer.Exit(code=1) from exc

    if exit_code != 0:
        console.print(f"[red]Deploy failed[/] with exit code {exit_code}")
        raise typer.Exit(code=exit_code)

    console.print("[green]Deploy completed successfully.[/]")


@app.command("monitor-gpu")
def monitor_gpu(
    interval: Annotated[Optional[float], typer.Option(help="Poll interval in seconds.")] = None,
    warn_pct: Annotated[Optional[float], typer.Option(help="VRAM warning threshold (%).")] = None,
) -> None:
    """Check VRAM and GPU utilization on the remote or local host."""
    cfg = _cfg()
    gpu_cfg = GPUConfig(
        poll_interval_seconds=interval or cfg.gpu.poll_interval_seconds,
        vram_warning_threshold_pct=warn_pct or cfg.gpu.vram_warning_threshold_pct,
    )

    console.print(Panel.fit("[bold magenta]Monitor GPU[/] - VRAM & utilization", border_style="magenta"))

    try:
        stats = check_gpu_usage(gpu_cfg)
    except NotImplementedError as exc:
        console.print(f"[yellow]Stub:[/] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="GPU Status", show_header=True, header_style="bold")
    table.add_column("GPU", style="dim")
    table.add_column("Name")
    table.add_column("VRAM Used (MB)", justify="right")
    table.add_column("VRAM Total (MB)", justify="right")
    table.add_column("Utilization (%)", justify="right")

    for row in stats:
        vram_used = float(row["vram_used_mb"])
        vram_total = float(row["vram_total_mb"])
        util = float(row["utilization_pct"])
        vram_pct = (vram_used / vram_total * 100) if vram_total else 0.0

        vram_style = "red" if vram_pct >= gpu_cfg.vram_warning_threshold_pct else "green"
        table.add_row(
            str(row["index"]),
            str(row["name"]),
            f"[{vram_style}]{vram_used:.0f}[/{vram_style}]",
            f"{vram_total:.0f}",
            f"{util:.1f}",
        )

    console.print(table)


@app.command("scan-prompt")
def scan_prompt_cmd(
    prompt: Annotated[Optional[str], typer.Argument(help="Prompt text to scan.")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Read prompt from a file.")] = None,
    listen_host: Annotated[Optional[str], typer.Option(help="Proxy listen host (stub).")] = None,
    listen_port: Annotated[Optional[int], typer.Option(help="Proxy listen port (stub).")] = None,
    upstream: Annotated[Optional[str], typer.Option(help="Upstream LLM URL (stub).")] = None,
) -> None:
    """Scan a prompt for injection attacks (placeholder proxy)."""
    cfg = _cfg()
    sec = SecurityConfig(
        listen_host=listen_host or cfg.security.listen_host,
        listen_port=listen_port or cfg.security.listen_port,
        upstream_url=upstream or cfg.security.upstream_url,
        block_on_injection=cfg.security.block_on_injection,
    )

    console.print(
        Panel.fit(
            f"[bold yellow]Scan Prompt[/] - proxy stub @ {sec.listen_host}:{sec.listen_port}",
            border_style="yellow",
        )
    )

    if file:
        text = file.read_text(encoding="utf-8")
    elif prompt:
        text = prompt
    else:
        console.print("[red]Provide a prompt argument or --file.[/]")
        raise typer.Exit(code=1)

    result = scan_prompt(text, sec)
    safe = bool(result["safe"])
    score = float(result["score"])
    reasons = result["reasons"]

    status = "[green]SAFE[/]" if safe else "[red]BLOCKED[/]"
    console.print(f"Verdict: {status}  |  Risk score: {score:.2f}")

    if reasons:
        console.print("[red]Matched indicators:[/]")
        for reason in reasons:
            console.print(f"  - {reason}")
    else:
        console.print("[dim]No injection indicators detected (stub heuristic).[/]")

    console.print(f"[dim]Upstream proxy target (not started): {sec.upstream_url}[/]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
