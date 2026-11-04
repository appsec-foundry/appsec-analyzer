"""Write the report's role names into `threat-model.yaml`.

Report, figures, exports and the canonical model then name every legitimate role
alike: "<project> User", "<project> Visitor" or "<project> Admin", owner-declared
roles as declared (`renderers.role_names`). Identities stay as they are. The pass
runs after self-registration is resolved, because that decides between Visitor
and User, and applying it again changes nothing.

Usage:
    python3 model/emit_role_names.py <output_dir>
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import sys
from pathlib import Path

import yaml
from renderers.role_names import apply_role_names
from shared._atomic_io import atomic_write_text


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: model/emit_role_names.py <output_dir>", file=sys.stderr)
        return 2
    path = Path(argv[0]) / "threat-model.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        print(f"emit_role_names: could not read {path}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print(f"emit_role_names: {path} did not parse to a mapping", file=sys.stderr)
        return 1
    before = [dict(e) for e in data.get("external_entities") or [] if isinstance(e, dict)]
    apply_role_names(data)
    if [dict(e) for e in data.get("external_entities") or [] if isinstance(e, dict)] != before:
        atomic_write_text(path, yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
