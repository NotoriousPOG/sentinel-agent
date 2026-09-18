"""CLI for ``python -m sentinel.evals run``."""

import argparse
from pathlib import Path

from sentinel.evals.dataset import default_dataset_path, load_dataset
from sentinel.evals.reports import format_summary, write_reports
from sentinel.evals.runner import excluded_labels_respected, execute, schema_compliance_total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel.evals")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the synthetic dataset and write reports")
    run.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="directory for report.json and report.md",
    )
    run.add_argument(
        "--dataset",
        type=Path,
        default=None,
        help="dataset JSON (default: evals/dataset.json)",
    )
    args = parser.parse_args(argv)
    if args.command != "run":
        parser.error("unknown command")
    dataset_path = default_dataset_path() if args.dataset is None else args.dataset
    dataset = load_dataset(dataset_path)
    report = execute(dataset, dataset_path=str(dataset_path))
    json_path, markdown_path = write_reports(report, args.output_dir)
    print(format_summary(report, json_path=json_path, markdown_path=markdown_path))
    if not schema_compliance_total(report) or not excluded_labels_respected(report):
        return 1
    return 0
