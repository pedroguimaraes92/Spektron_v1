#!/usr/bin/env python3

import os
from pathlib import Path

EXCLUDES = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build"
}


def human_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def should_skip(path: Path):
    return any(part in EXCLUDES for part in path.parts)


def main():
    root = Path.cwd()
    directory_data = {}

    # First pass: collect sizes per directory (direct files only)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDES]

        current = Path(dirpath)
        if should_skip(current):
            continue

        size = 0
        file_count = 0

        for file in filenames:
            fp = current / file
            try:
                stat = fp.stat()
                size += stat.st_size
                file_count += 1
            except Exception:
                continue

        rel = str(current.relative_to(root)) if current != root else "."
        directory_data[rel] = {
            "size_bytes": size,
            "file_count": file_count,
        }

    # Second pass: accumulate subdirectory sizes
    for path in sorted(directory_data.keys(), key=lambda x: x.count("/"), reverse=True):
        if path == ".":
            continue
        parent = "." if "/" not in path else path.rsplit("/", 1)[0]
        if parent in directory_data:
            directory_data[parent]["size_bytes"] += directory_data[path]["size_bytes"]

    # Print results
    print("\nSpektron Directory Map\n")
    print(f"Root: {root}\n")

    total_size = directory_data["."]["size_bytes"]
    print(f"Total repo size: {human_size(total_size)}\n")

    print("Directory Tree (size | files):\n")

    for path in sorted(directory_data.keys()):
        size = directory_data[path]["size_bytes"]
        files = directory_data[path]["file_count"]
        print(f"{path:<60} {human_size(size):>10} | {files} files")

    empty_dirs = [p for p, v in directory_data.items() if v["size_bytes"] == 0]

    print("\nEmpty directories:")
    for d in empty_dirs:
        print(" -", d)

    print("\nDone.\n")


if __name__ == "__main__":
    main()