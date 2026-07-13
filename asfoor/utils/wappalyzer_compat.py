"""Compatibility shim for python-Wappalyzer on Python 3.12+.

python-Wappalyzer's source does ``import pkg_resources`` at module level.
``pkg_resources`` was part of ``setuptools`` but has been deprecated since
setuptools 67 and **removed entirely** in recent setuptools releases (≥ 74 on
Python 3.12+, ≥ 83 on 3.13+).  Python 3.14 will never ship pkg_resources.

This module provides a minimal stub that satisfies the single call Wappalyzer
makes::

    pkg_resources.resource_string(__name__, "data/technologies.json")

The stub is registered in ``sys.modules`` so that when Wappalyzer later does
``import pkg_resources``, it finds our shim instead of raising
``ModuleNotFoundError``.

**Usage** — import this module *before* any ``from Wappalyzer import …``::

    import asfoor.utils.wappalyzer_compat  # noqa: F401  (side-effect import)
    from Wappalyzer import Wappalyzer, WebPage
"""
from __future__ import annotations

import importlib
import sys
import types
from importlib.resources import files as _pkg_files
from pathlib import Path


def _ensure_pkg_resources() -> None:
    """Install a minimal ``pkg_resources`` stub if the real one is missing."""
    try:
        importlib.import_module("pkg_resources")
        return  # already available — nothing to do
    except ModuleNotFoundError:
        pass

    # Build a tiny stub module with the only function Wappalyzer uses.
    stub = types.ModuleType("pkg_resources")
    stub.__doc__ = "Minimal stub for python-Wappalyzer compatibility (provided by 3asfoor)."
    stub.__file__ = __file__
    stub.__package__ = "pkg_resources"

    def resource_string(package_name: str, resource_path: str) -> bytes:
        """Read a package resource as bytes — mirrors the real API."""
        try:
            ref = _pkg_files(package_name).joinpath(*resource_path.split("/"))
            return ref.read_bytes()
        except Exception:
            # Last-resort fallback: resolve via the package's __file__
            pkg = importlib.import_module(package_name)
            pkg_dir = Path(pkg.__file__).parent
            return (pkg_dir / resource_path).read_bytes()

    stub.resource_string = resource_string

    sys.modules["pkg_resources"] = stub


# Run the shim on import so callers only need:
#     import asfoor.utils.wappalyzer_compat  # noqa: F401
_ensure_pkg_resources()

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module=".*Wappalyzer.*")

