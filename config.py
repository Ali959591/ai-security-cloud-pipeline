"""Application configuration for the AI Security Cloud CLI."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SSHConfig:
    """Remote host connection settings for GPU deploy runs."""

    host: str = "localhost"
    port: int = 22
    user: str = "ubuntu"
    key_path: Path | None = None
    remote_workdir: str = "~/ai-runs"


@dataclass
class GPUConfig:
    """GPU monitoring defaults."""

    poll_interval_seconds: float = 2.0
    vram_warning_threshold_pct: float = 90.0


@dataclass
class SecurityConfig:
    """Prompt injection scan proxy settings."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    upstream_url: str = "http://localhost:11434"
    block_on_injection: bool = True


@dataclass
class AppConfig:
    """Top-level CLI configuration."""

    ssh: SSHConfig = field(default_factory=SSHConfig)
    gpu: GPUConfig = field(default_factory=GPUConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)


def load_config() -> AppConfig:
    """Return the active application configuration."""
    return AppConfig()
