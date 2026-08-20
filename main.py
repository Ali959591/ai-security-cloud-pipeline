"""AI Security and Remote Cloud CLI."""

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import AppConfig, GPUConfig, SecurityConfig, SSHConfig, load_config
from utils.gpu import check_gpu_usage
from utils.security import scan_prompt
from utils.ssh import SSHConnectionError, deploy_via_ssh

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
    password: Annotated[Optional[str], typer.Option(help="SSH password (uses key/agent if omitted).", hide_input=True)] = None,
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
        exit_code = deploy_via_ssh(ssh, command=command, dry_run=dry_run, password=password, console=console)
    except SSHConnectionError as exc:
        console.print(f"[red]Connection error:[/] {exc}")
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


def _risk_style(score: float) -> str:
    if score >= 0.7:
        return "red"
    if score >= 0.35:
        return "yellow"
    return "green"


def _risk_bar(score: float, width: int = 24) -> Text:
    filled = round(score * width)
    style = _risk_style(score)
    bar = Text()
    bar.append("#" * filled, style=style)
    bar.append("-" * (width - filled), style="dim")
    return bar


def _render_scan_result(result: dict[str, object], sec: SecurityConfig) -> None:
    score = float(result["score"])
    safe = bool(result["safe"])
    matches = result["matches"]
    timestamp = str(result["timestamp"])
    preview = str(result["prompt_preview"])
    prompt_length = int(result["prompt_length"])

    verdict_style = "green" if safe else "red"
    verdict_label = "SAFE" if safe else "BLOCKED"
    if not safe and sec.block_on_injection:
        verdict_detail = f"score >= threshold ({sec.risk_threshold:.2f})"
    elif score > 0:
        verdict_detail = f"below threshold ({sec.risk_threshold:.2f})"
    else:
        verdict_detail = "no indicators matched"

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Verdict", Text(verdict_label, style=f"bold {verdict_style}"))
    summary.add_row("Risk score", Text(f"{score:.3f}", style=_risk_style(score)))
    summary.add_row("Risk bar", _risk_bar(score))
    summary.add_row("Detail", verdict_detail)
    summary.add_row("Scanned at", timestamp)
    summary.add_row("Prompt length", f"{prompt_length} chars")
    summary.add_row("History log", str(sec.scan_history_path))

    console.print(Panel(summary, title="Scan Result", border_style=verdict_style))

    console.print(Panel(preview or "[dim](empty prompt)[/]", title="Prompt preview", border_style="dim"))

    if matches:
        match_table = Table(title="Matched Heuristics", show_header=True, header_style="bold")
        match_table.add_column("Category", style="cyan")
        match_table.add_column("Indicator")
        match_table.add_column("Weight", justify="right")
        match_table.add_column("Context", style="dim", overflow="fold")

        for match in matches:
            match_table.add_row(
                str(match["category"]),
                str(match["label"]),
                f"{float(match['weight']):.2f}",
                str(match["snippet"]),
            )
        console.print(match_table)
    else:
        console.print("[green]No injection or obfuscation indicators detected.[/]")

    console.print(f"[dim]Logged to {sec.scan_history_path}[/]")


@app.command("scan-prompt")
def scan_prompt_cmd(
    prompt: Annotated[Optional[str], typer.Argument(help="Prompt text to scan.")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Read prompt from a file.")] = None,
    threshold: Annotated[Optional[float], typer.Option(help="Risk score threshold for blocking (0.0-1.0).")] = None,
    history: Annotated[Optional[Path], typer.Option(help="Path to scan history JSON log.")] = None,
    listen_host: Annotated[Optional[str], typer.Option(help="Proxy listen host (future use).")] = None,
    listen_port: Annotated[Optional[int], typer.Option(help="Proxy listen port (future use).")] = None,
    upstream: Annotated[Optional[str], typer.Option(help="Upstream LLM URL (future use).")] = None,
) -> None:
    """Scan a prompt for injection attacks and log results locally."""
    cfg = _cfg()
    sec = SecurityConfig(
        listen_host=listen_host or cfg.security.listen_host,
        listen_port=listen_port or cfg.security.listen_port,
        upstream_url=upstream or cfg.security.upstream_url,
        block_on_injection=cfg.security.block_on_injection,
        risk_threshold=threshold if threshold is not None else cfg.security.risk_threshold,
        scan_history_path=history or cfg.security.scan_history_path,
    )

    console.print(
        Panel.fit(
            f"[bold yellow]Prompt Security Scanner[/]  threshold={sec.risk_threshold:.2f}",
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
    _render_scan_result(result, sec)

    if not result["safe"]:
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
