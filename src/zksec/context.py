"""Baseline security context declarations for zkSEC."""

from __future__ import annotations

SECURITY_CONTEXT_VERSION = "0.1.0"


def load_security_context() -> dict[str, object]:
    """Return baseline security context metadata."""
    return {
        "version": SECURITY_CONTEXT_VERSION,
        "project": "zkSEC",
        "chat_thread_title": "LiteLLM hack analysis",
        "chat_thread_online_uuid": "69ce0ac6-dd2c-839f-8b84-a0d397285f90",
        "chat_thread_canonical_id": "130c635a73d780dfb0552107cc0a77a77d4cfea9",
        "source": "db",
    }


def known_adjacent_surfaces() -> list[str]:
    """Return adjacent repos/files currently treated as relevant."""
    return [
        "../ITIR-suite",
        "../zos-server",
        "../zkperf",
        "../ipfs-dasl",
        "../kant-zk-pastebin",
    ]
