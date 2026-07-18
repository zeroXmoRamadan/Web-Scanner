"""Central logging setup."""
from __future__ import annotations

import logging
import sys
from pathlib import Path


def setup_logger(output_dir: str = "./output", verbose: bool = False, quiet: bool = False) -> logging.Logger:
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    level = logging.DEBUG if verbose else logging.ERROR

    logger = logging.getLogger("asfoor")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(fmt)
    logger.addHandler(console)

    file_handler = logging.FileHandler(Path(output_dir) / "scan.log", mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger
