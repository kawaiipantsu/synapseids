"""Make ``synapse_trainer`` importable when the package is not pip-installed.

``python -m pytest trainer/`` from the repo root works without an editable
install because this conftest (collected as soon as pytest descends into
``trainer/``) prepends the directory to ``sys.path``.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
