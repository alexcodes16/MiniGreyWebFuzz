"""Generate a coverage growth plot from reports/coverage_history.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot MiniGreyWebFuzz coverage growth")
    parser.add_argument(
        "--history-path",
        type=Path,
        default=Path("reports/coverage_history.json"),
        help="Path to coverage history JSON",
    )
    parser.add_argument(
        "--output-path",
        type=Path,
        default=Path("reports/coverage_growth.png"),
        help="Path to output PNG",
    )
    return parser.parse_args()


def load_coverage_history(path: Path) -> list[dict[str, int]]:
    if not path.exists():
        raise FileNotFoundError(f"Coverage history file not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("coverage history must be a list")

    rows: list[dict[str, int]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        request_index = int(item.get("request_index", 0))
        coverage_count = int(item.get("coverage_count", 0))
        rows.append({"request_index": request_index, "coverage_count": coverage_count})
    return rows


def plot_coverage_growth(history: list[dict[str, int]], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    x = [row["request_index"] for row in history]
    y = [row["coverage_count"] for row in history]

    plt.figure(figsize=(8, 4.5))
    plt.plot(x, y, marker="o", linewidth=2)
    plt.title("MiniGreyWebFuzz Coverage Growth")
    plt.xlabel("request_index")
    plt.ylabel("coverage_count")
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    return output_path


def main() -> int:
    args = parse_args()
    history = load_coverage_history(args.history_path)

    if not history:
        raise ValueError("coverage history is empty; run the fuzzer first")

    output = plot_coverage_growth(history, args.output_path)
    print(f"Saved coverage plot to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
