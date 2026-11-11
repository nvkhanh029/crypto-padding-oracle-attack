"""Generate the four pinned SCOWL flat lists without shell-specific encoding."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

PINNED_COMMIT = "1e5b7d3a72f47a71da5d28686c1dd4b397178485"
EXPECTED_LINES = {60: 109_140, 70: 166_817, 80: 241_867, 85: 298_937}


def extract_lists(scowl_dir: Path, output_dir: Path) -> None:
    scowl_dir = scowl_dir.resolve()
    if not (scowl_dir / "combine.py").is_file() or not (scowl_dir / "scowl").is_file():
        raise FileNotFoundError("scowl-dir must be the root of the pinned SCOWL checkout")
    if (scowl_dir / ".git").exists():
        revision = subprocess.run(
            ["git", "-C", str(scowl_dir), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if revision != PINNED_COMMIT:
            raise ValueError(f"expected SCOWL commit {PINNED_COMMIT}, found {revision}")
    elif PINNED_COMMIT not in scowl_dir.name:
        raise ValueError(
            f"checkout must be at {PINNED_COMMIT}, or use its unrenamed archive directory"
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="scowl-build-") as temp:
        database = Path(temp) / "scowl.db"
        subprocess.run(
            [sys.executable, str(scowl_dir / "combine.py"), "create-db", str(database)],
            cwd=scowl_dir,
            check=True,
        )
        for size, expected_count in EXPECTED_LINES.items():
            result = subprocess.run(
                [
                    sys.executable, str(scowl_dir / "scowl"), "--db", str(database),
                    "word-list", str(size), "A", "1", "--deaccent",
                ],
                cwd=scowl_dir,
                check=True,
                capture_output=True,
            )
            # Use LF line endings on every OS, so the SHA-256 is the same everywhere.
            data = result.stdout.replace(b"\r\n", b"\n")
            lines = data.splitlines()
            if len(lines) != expected_count:
                raise ValueError(
                    f"wl{size}.txt: expected {expected_count} lines, found {len(lines)}"
                )
            (output_dir / f"wl{size}.txt").write_bytes(data)
            print(f"wl{size}.txt: {len(lines):,} lines")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scowl-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("data/wordlist/source"))
    args = parser.parse_args()
    extract_lists(args.scowl_dir, args.output_dir)


if __name__ == "__main__":
    main()
