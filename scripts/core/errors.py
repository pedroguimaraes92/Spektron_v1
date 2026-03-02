from __future__ import annotations

class SpektronError(Exception):
    """Base error."""

class InputError(SpektronError):
    """Invalid user input."""

class ProbeError(SpektronError):
    """A probe failed in a handled way."""
