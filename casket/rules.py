"""Load casket's YAML rule configs.

Rules ship bundled with the package under ``casket/rules/``. A user may point
casket at an alternative rules directory; v0.1 only wires the bundled defaults.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_RULEDATA = Path(__file__).resolve().parent / "ruledata"


@lru_cache(maxsize=None)
def load_ruleset(name: str) -> list[dict[str, Any]]:
    """Load the rule list from ``casket/ruledata/<name>.yaml``."""
    text = (_RULEDATA / f"{name}.yaml").read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    return data.get("rules", [])
