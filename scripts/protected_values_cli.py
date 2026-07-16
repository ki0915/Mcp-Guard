"""Compatibility wrapper for :mod:`dlp_proxy.registry_cli`."""

from dlp_proxy.registry_cli import (
    REPO_ROOT,
    add_allowlist_entry,
    add_entry,
    allowlist_entry,
    literal_entry,
    main,
    probe_value,
    remove_record,
    safe_inventory,
    token_entry,
)

__all__ = [
    "REPO_ROOT",
    "add_allowlist_entry",
    "add_entry",
    "allowlist_entry",
    "literal_entry",
    "main",
    "probe_value",
    "remove_record",
    "safe_inventory",
    "token_entry",
]


if __name__ == "__main__":
    raise SystemExit(main())
