"""``python -m synapse_trainer`` -> :func:`synapse_trainer.cli.main`."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
