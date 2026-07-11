"""Generate synthetic RRN test samples with correct/incorrect check digits.

The bodies are synthetic (fake serials); only the checksum math is real.
Used once to build tests/data fixtures.
"""

WEIGHTS = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)


def check_digit(d12: str) -> int:
    total = sum(int(d12[i]) * WEIGHTS[i] for i in range(12))
    return (11 - total % 11) % 10


bases = [
    # All-zero serial portions make these conspicuously synthetic while the
    # final digit still exercises the real mod-11 checksum implementation.
    "800101100000",
    "900101200000",
    "750615100000",
    "020304300000",
    "851122200000",
]
for b in bases:
    c = check_digit(b)
    bad = (c + 1) % 10
    print(f"valid:   {b[:6]}-{b[6:]}{c}    invalid-checksum: {b[:6]}-{b[6:]}{bad}")
