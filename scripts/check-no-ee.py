import os
import sys
from pathlib import Path


def check(root: Path) -> int:
    def fail(error: OSError) -> None:
        raise error

    for parent, directories, _ in os.walk(root, onerror=fail):
        if ".git" in directories:
            directories.remove(".git")
        if "ee" in directories:
            print(f"Enterprise-only directory is not allowed: {Path(parent) / 'ee'}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    if not root.is_dir():
        raise SystemExit(f"Repository directory does not exist: {root}")
    raise SystemExit(check(root))
