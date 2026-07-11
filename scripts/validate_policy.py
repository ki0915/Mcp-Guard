"""Fail-fast policy validator that never prints matcher or protected values."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dlp_proxy import policy  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", default="configs/policy.yaml")
    parser.add_argument("--protected-values")
    args = parser.parse_args()
    try:
        loaded = policy.load(args.policy, args.protected_values)
    except (OSError, ValueError) as exc:
        print(f"invalid configuration: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(loaded.safe_summary(), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
