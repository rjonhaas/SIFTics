"""Load labels.yaml and expose the active label set."""
from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import yaml


@cache
def load_labels(path: Path | str | None = None) -> dict[str, Any]:
    if path is None:
        path = Path(__file__).parent / "labels.yaml"
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    active = data["active_label_set"]
    labels = dict(data["label_sets"][active])
    labels["__active_set__"] = active
    return labels
