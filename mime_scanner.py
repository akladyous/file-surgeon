"""
mime_scanner.py
---------------
Production-grade file MIME type scanner using Google's Magika library.

Usage (CLI):
    python mime_scanner.py -filepath /some/path
    python mime_scanner.py -filepath /some/file.pdf --output json
    python mime_scanner.py -filepath /some/folder --recursive --log-level DEBUG

Usage (as module):
    from mime_scanner import scan_path, scan_files

    results = scan_path("/some/folder", recursive=True)
    results = scan_files(["/a.pdf", "/b.zip"])
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Optional dependency guard — give a clear error if Magika is not installed
# ---------------------------------------------------------------------------
try:
    from magika import Magika
    from magika.types import MagikaResult
except ImportError as exc:  # pragma: no cover
    sys.exit(
        "Magika is not installed. Run:  pip install magika\n" f"Original error: {exc}"
    )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
logger = logging.getLogger(__name__)


def _configure_logging(level: str = "WARNING") -> None:
    """Configure root logger. Called once from the CLI entry-point."""
    logging.basicConfig(level=level.upper(), format=LOG_FORMAT)


# ---------------------------------------------------------------------------
# Public data model
# ---------------------------------------------------------------------------


class ScanStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class FileScanResult:
    """Holds the scan result for a single file."""

    path: str
    mime_type: str | None
    label: str | None
    status: ScanStatus
    error: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------


def _iter_files(root: Path, recursive: bool) -> Iterator[Path]:
    """Yield file paths under *root*, optionally traversing sub-directories."""
    if root.is_file():
        yield root
        return

    pattern = "**/*" if recursive else "*"
    for entry in root.glob(pattern):
        if entry.is_file():
            yield entry


def scan_files(
    file_paths: list[str | Path],
    *,
    magika_instance: Magika | None = None,
) -> list[FileScanResult]:
    """
    Scan an explicit list of files and return their MIME type results.

    Parameters
    ----------
    file_paths:
        Absolute or relative paths to the files to scan.
    magika_instance:
        Optional pre-constructed Magika instance (useful for reuse / testing).

    Returns
    -------
    list[FileScanResult]
    """
    if not file_paths:
        logger.warning("scan_files() called with an empty file list.")
        return []

    mg = magika_instance or Magika()
    results: list[FileScanResult] = []

    for raw_path in file_paths:
        path = Path(raw_path)
        logger.debug("Scanning: %s", path)

        if not path.exists():
            logger.warning("File not found, skipping: %s", path)
            results.append(
                FileScanResult(
                    path=str(path),
                    mime_type=None,
                    label=None,
                    status=ScanStatus.SKIPPED,
                    error="File not found",
                )
            )
            continue

        try:
            with path.open("rb") as fh:
                result: MagikaResult = mg.identify_stream(fh)

            results.append(
                FileScanResult(
                    path=str(path),
                    mime_type=result.output.mime_type,
                    label=result.output.label,
                    status=ScanStatus.OK,
                )
            )
            logger.debug("Result for %s → %s", path, result.output.label)

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to scan %s: %s", path, exc, exc_info=True)
            results.append(
                FileScanResult(
                    path=str(path),
                    mime_type=None,
                    label=None,
                    status=ScanStatus.ERROR,
                    error=str(exc),
                )
            )

    return results


def scan_path(
    path: str | Path,
    *,
    recursive: bool = False,
    magika_instance: Magika | None = None,
) -> list[FileScanResult]:
    """
    Scan a file or directory and return MIME type results.

    Parameters
    ----------
    path:
        Path to a file or directory.
    recursive:
        If True and *path* is a directory, traverse sub-directories.
    magika_instance:
        Optional pre-constructed Magika instance.

    Returns
    -------
    list[FileScanResult]

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    NotADirectoryError
        If *path* is neither a file nor a directory.
    """
    root = Path(path)

    if not root.exists():
        raise FileNotFoundError(f"Path does not exist: {root}")
    if not root.is_file() and not root.is_dir():
        raise NotADirectoryError(f"Path is neither a file nor a directory: {root}")

    file_list = list(_iter_files(root, recursive=recursive))
    logger.info(
        "Discovered %d file(s) under '%s' (recursive=%s)",
        len(file_list),
        root,
        recursive,
    )

    return scan_files(file_list, magika_instance=magika_instance)


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


class OutputFormat(str, Enum):
    JSON = "json"
    TABLE = "table"
    CSV = "csv"


def _format_json(results: list[FileScanResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=4)


def _format_table(results: list[FileScanResult]) -> str:
    if not results:
        return "(no results)"

    col_path = max(len(r.path) for r in results)
    col_label = max(len(r.label or "—") for r in results)
    col_mime = max(len(r.mime_type or "—") for r in results)
    col_status = max(len(r.status.value) for r in results)

    header = (
        f"{'PATH':<{col_path}}  {'LABEL':<{col_label}}  "
        f"{'MIME TYPE':<{col_mime}}  {'STATUS':<{col_status}}  ERROR"
    )
    sep = "-" * (len(header) + 20)
    rows = [header, sep]

    for r in results:
        rows.append(
            f"{r.path:<{col_path}}  {(r.label or '—'):<{col_label}}  "
            f"{(r.mime_type or '—'):<{col_mime}}  {r.status.value:<{col_status}}  "
            f"{r.error or ''}"
        )
    return "\n".join(rows)


def _format_csv(results: list[FileScanResult]) -> str:
    import csv
    import io

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=["path", "mime_type", "label", "status", "error"]
    )
    writer.writeheader()
    for r in results:
        writer.writerow(r.to_dict())
    return buf.getvalue()


_FORMATTERS = {
    OutputFormat.JSON: _format_json,
    OutputFormat.TABLE: _format_table,
    OutputFormat.CSV: _format_csv,
}


def format_results(
    results: list[FileScanResult], fmt: OutputFormat = OutputFormat.JSON
) -> str:
    """Render *results* using the requested output format."""
    return _FORMATTERS[fmt](results)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mime_scanner",
        description="Identify MIME types for files using Google Magika.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-filepath",
        dest="filepath",
        type=str,
        default=".",
        metavar="PATH",
        help="File or directory to scan.",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        default=False,
        help="Recurse into sub-directories.",
    )
    parser.add_argument(
        "--output",
        choices=[f.value for f in OutputFormat],
        default=OutputFormat.TABLE.value,
        help="Output format.",
    )
    parser.add_argument(
        "--log-level",
        dest="log_level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="WARNING",
        help="Logging verbosity.",
    )
    parser.add_argument(
        "--fail-on-error",
        dest="fail_on_error",
        action="store_true",
        default=False,
        help="Exit with code 2 if any file could not be scanned.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    CLI entry-point.

    Returns
    -------
    int
        Exit code — 0 on success, 1 on usage error, 2 on scan errors (when
        --fail-on-error is set).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    _configure_logging(args.log_level)

    try:
        results = scan_path(
            args.filepath,
            recursive=args.recursive,
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        logger.critical(exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    fmt = OutputFormat(args.output)
    print(format_results(results, fmt))

    if args.fail_on_error:
        errors = [r for r in results if r.status == ScanStatus.ERROR]
        if errors:
            logger.warning("%d file(s) failed to scan.", len(errors))
            return 2

    return 0


# ---------------------------------------------------------------------------
# Entry-point guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())
