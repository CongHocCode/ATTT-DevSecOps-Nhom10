"""Convert Trivy filesystem and image JSON reports into experiment metrics CSV."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, OSError):
        pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HEADERS = [
    "Run_ID",
    "Repeat_No",
    "Commit_Hash",
    "Test_Scenario",
    "Scanner_Name",
    "Execution_Time_Sec",
    "Pipeline_Total_Sec",
    "Raw_Findings",
    "Critical_Findings",
    "True_Positives",
    "False_Positives",
    "Missed_Findings",
    "Max_Severity",
    "Quality_Gate_Status",
    "Notes",
]
SEVERITY_WEIGHT = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as report_file:
            report = json.load(report_file)
    except FileNotFoundError as error:
        raise ValueError(f"Không tìm thấy báo cáo JSON: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"JSON không hợp lệ tại {path}: {error}") from error

    if not isinstance(report, dict):
        raise ValueError(f"Báo cáo phải là JSON object: {path}")
    return report


def parse_trivy_report(path: Path) -> tuple[int, int, str]:
    report = read_json(path)
    results = report.get("Results", [])
    if not isinstance(results, list):
        raise ValueError(f"Trường Results phải là danh sách: {path}")

    severities: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError(f"Một phần tử Results không hợp lệ: {path}")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError(f"Vulnerabilities phải là danh sách: {path}")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError(f"Một vulnerability không hợp lệ: {path}")
            severities.append(str(vulnerability.get("Severity", "UNKNOWN")).upper())

    highest = max(
        severities,
        key=lambda value: SEVERITY_WEIGHT.get(value, 0),
        default="UNKNOWN",
    )
    return len(severities), sum(value == "CRITICAL" for value in severities), highest


def quality_gate_status(critical_findings: int, trivy_exit_code: Any) -> str:
    if not isinstance(trivy_exit_code, int):
        return "INCOMPLETE"
    return "FAILED" if critical_findings > 0 or trivy_exit_code != 0 else "PASSED"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Đọc JSON Trivy FS/Image và nối số liệu thực nghiệm vào CSV."
    )
    parser.add_argument("--fs-report", default="trivy-reports/trivy-fs-report.json")
    parser.add_argument(
        "--image-report", default="trivy-reports/trivy-image-report.json"
    )
    parser.add_argument("--timing", default="trivy-reports/trivy-timing.json")
    parser.add_argument("--output", default=os.environ.get("OUTPUT_CSV", "results_metrics.csv"))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID"))
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--scenario", default="Patched")
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "local"))
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Tạo CSV mới; hãy sao lưu file hiện có trước khi dùng.",
    )
    args = parser.parse_args()

    if args.repeat < 1:
        parser.error("--repeat phải là số nguyên dương")

    run_id = args.run_id or datetime.now(timezone.utc).strftime("local-%Y%m%dT%H%M%SZ")

    try:
        fs_path = resolve_path(args.fs_report)
        image_path = resolve_path(args.image_report)
        timing_path = resolve_path(args.timing)
        output_path = resolve_path(args.output)

        fs_total, fs_critical, fs_max = parse_trivy_report(fs_path)
        image_total, image_critical, image_max = parse_trivy_report(image_path)
        timing = read_json(timing_path)

        fs_time = timing["trivy_fs_execution_time_sec"]
        image_time = timing["trivy_image_execution_time_sec"]
        total_time = timing["trivy_pipeline_total_sec"]
        fs_exit = timing["trivy_fs_gate_exit_code"]
        image_exit = timing["trivy_image_gate_exit_code"]

        for label, value in (
            ("thời gian FS", fs_time),
            ("thời gian image", image_time),
            ("tổng thời gian", total_time),
        ):
            if not isinstance(value, (int, float)) or value < 0:
                raise ValueError(f"{label} phải là số không âm")

        scans = [
            (
                "Trivy (FS)", fs_time, fs_total, fs_critical, fs_max,
                quality_gate_status(fs_critical, fs_exit),
                "Báo cáo filesystem; Raw_Findings gồm mọi severity.",
            ),
            (
                "Trivy (Image)", image_time, image_total, image_critical, image_max,
                quality_gate_status(image_critical, image_exit),
                "Báo cáo Docker image; Raw_Findings gồm mọi severity.",
            ),
        ]

        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists() and output_path.stat().st_size > 0 and not args.reset:
            with output_path.open("r", newline="", encoding="utf-8-sig") as old_csv:
                existing_headers = next(csv.reader(old_csv), [])
            if existing_headers != HEADERS:
                raise ValueError(
                    f"Header của {output_path} không khớp schema hiện tại. "
                    "Sao lưu CSV cũ rồi chạy lần đầu với --reset."
                )

        mode = "w" if args.reset else "a"
        needs_header = args.reset or not output_path.exists() or output_path.stat().st_size == 0
        with output_path.open(mode, newline="", encoding="utf-8-sig") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=HEADERS)
            if needs_header:
                writer.writeheader()
            for name, duration, total, critical, highest, status, notes in scans:
                writer.writerow(
                    {
                        "Run_ID": run_id,
                        "Repeat_No": args.repeat,
                        "Commit_Hash": args.commit,
                        "Test_Scenario": args.scenario,
                        "Scanner_Name": name,
                        "Execution_Time_Sec": f"{duration:.3f}",
                        "Pipeline_Total_Sec": f"{total_time:.3f}",
                        "Raw_Findings": total,
                        "Critical_Findings": critical,
                        "True_Positives": "",
                        "False_Positives": "",
                        "Missed_Findings": "",
                        "Max_Severity": highest,
                        "Quality_Gate_Status": status,
                        "Notes": notes,
                    }
                )

        print(f"Đã ghi {len(scans)} dòng vào {output_path}")
        for name, duration, total, critical, highest, status, _ in scans:
            print(
                f"{name}: findings={total}, critical={critical}, max={highest}, "
                f"gate={status}, time={duration:.3f}s"
            )
        return 0
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(f"Lỗi tạo CSV: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
