"""Create a SHA-256 protected-token entry without shell-history exposure."""

from __future__ import annotations

import getpass
import hashlib
import re

_ASCII_TOKEN = re.compile(r"^[A-Za-z0-9_./+=:@#$%!?~-]{8,512}$")


def digest_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def main() -> int:
    value = getpass.getpass("Protected ASCII token (hidden): ")
    confirmation = getpass.getpass("Confirm token (hidden): ")
    if value != confirmation:
        print("Tokens do not match.")
        return 2
    if not _ASCII_TOKEN.fullmatch(value):
        print("Token must be 8-512 characters from the documented ascii_token charset.")
        return 2
    print(f"sha256: {digest_value(value)}")
    print("token:")
    print("  charset: ascii_token")
    print(f"  length: {len(value)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
