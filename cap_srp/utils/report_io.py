"""Write local reports without replacing the input evidence through a path alias."""

from pathlib import Path


def write_report(input_path: str | Path, output_path: str | Path, text: str) -> None:
    """Reject the input path and its existing symlink/hardlink aliases before writing.

    A distinct existing report may still be replaced, as before. This is a path
    identity check, not synchronization with concurrent filesystem writers.
    """
    try:
        source = Path(input_path).resolve()
        destination = Path(output_path).resolve()
    except RuntimeError as exc:
        # Python 3.10–3.12 report symlink loops as RuntimeError, not OSError.
        raise ValueError("Report path could not be resolved") from exc
    if source == destination or (destination.exists() and source.samefile(destination)):
        raise ValueError("Report output must not refer to the input event log")
    with destination.open("w", encoding="utf-8") as report:
        report.write(text)
