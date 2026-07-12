"""Loads and merges YAML configuration with CLI overrides."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load YAML config from `path`, falling back to the bundled default."""
    config_path = path or DEFAULT_CONFIG_PATH
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def merge_overrides(base_config: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Shallow-merge CLI-provided overrides (dot-path keys like 'port_scan.timing_template')
    into a copy of the base config. Ignores None values so unset CLI flags don't clobber
    config file settings.
    """
    merged = copy.deepcopy(base_config)
    for dotted_key, value in overrides.items():
        if value is None:
            continue
        parts = dotted_key.split(".")
        node = merged
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return merged
