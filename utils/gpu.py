"""GPU monitoring helpers."""

from config import GPUConfig


def check_gpu_usage(config: GPUConfig) -> list[dict[str, float | str]]:
    """
    Return VRAM and utilization stats for each detected GPU.

    Each entry includes: index, name, vram_used_mb, vram_total_mb, utilization_pct.
    """
    # TODO: parse nvidia-smi or query remote host over SSH
    _ = config
    raise NotImplementedError("GPU monitoring is not implemented yet.")
