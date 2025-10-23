#!/usr/bin/env python3
"""Command-line interface for DB Mapper."""

import argparse
import sys
import os
import signal
from pathlib import Path

from .runner import run_scan


def main():
    # Handle Ctrl+C gracefully
    def signal_handler(signum, frame):
        print("\nScan interrupted by user. Exiting gracefully...", file=sys.stderr)
        sys.exit(130)  # Standard exit code for SIGINT

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(
        description="DB Mapper - Static repository scanner for database-related artifacts",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "path",
        type=Path,
        help="Repository path to scan",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("output.json"),
        help="Output file path",
    )

    parser.add_argument(
        "--formats",
        nargs="+",
        choices=["json", "html", "graph", "csv"],
        default=["json"],
        help="Output formats",
    )

    parser.add_argument(
        "--include",
        nargs="+",
        help="Glob patterns for files to include",
    )

    parser.add_argument(
        "--exclude",
        nargs="+",
        help="Glob patterns for files to exclude",
    )

    parser.add_argument(
        "--languages",
        nargs="+",
        choices=["python", "javascript", "java", "csharp", "php", "ruby", "go", "sql"],
        help="Limit scan to specific languages",
    )

    parser.add_argument(
        "--plugins",
        nargs="+",
        help="Enable additional detector plugins",
    )

    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.5,
        help="Minimum confidence threshold for findings",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    parser.add_argument(
    "--threads",
    type=int,
    default=min(os.cpu_count() or 4, 16),
    help="Number of parallel worker threads (default: min(CPU count, 16))",
    )

    args = parser.parse_args()

    try:
        run_scan(args)
    except Exception as e:
        print(f"Error during scan: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
