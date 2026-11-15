"""Combine repeated Trivy FS/image JSON reports into experiment metrics CSV."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
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
    "Scanner_Version",
    "Vulnerability_DB_Warmed_At_UTC",
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
FS_REPORT_PATTERN = re.compile(r"trivy-fs-report-(\d+)\.json$")


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as report_file:
            report = json.load(report_file)
    except FileNotFoundError as error:
        raise ValueError(f"Không tìm thấy báo cáo JSON: {path}") from error
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ValueError(f"JSON không hợp lệ tại {path}: {error}") from error

    if not isinstance(report, dict):
        raise ValueError(f"Báo cáo phải là JSON object: {path}")
    return report


def parse_trivy_report(path: Path) -> tuple[int, int, str]:
    report = read_json(path)
    if "Results" not in report:
        raise ValueError(f"Báo cáo thiếu trường Results, không thể xác nhận quét sạch: {path}")
    results = report["Results"]
    if results is None:
        results = []
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
    critical_count = sum(value == "CRITICAL" for value in severities)
    return len(severities), critical_count, highest


def gate_status(critical_findings: int, exit_code: Any) -> str:
    if not isinstance(exit_code, int):
        return "INCOMPLETE"
    return "FAILED" if critical_findings > 0 or exit_code != 0 else "PASSED"


def load_repeats(reports_dir: Path) -> list[dict[str, Any]]:
    fs_reports = sorted(
        (path for path in reports_dir.glob("trivy-fs-report-*.json")
         if FS_REPORT_PATTERN.fullmatch(path.name)),
        key=lambda path: int(FS_REPORT_PATTERN.fullmatch(path.name).group(1)),
    )
    if not fs_reports:
        raise ValueError(f"Không tìm thấy trivy-fs-report-NN.json trong {reports_dir}")

    repeats = []
    seen = set()
    for fs_path in fs_reports:
        match = FS_REPORT_PATTERN.fullmatch(fs_path.name)
        repeat_no = int(match.group(1))
        if repeat_no in seen:
            raise ValueError(f"Trùng số lần lặp {repeat_no} trong {reports_dir}")
        seen.add(repeat_no)
        repeat_id = match.group(1)
        image_path = reports_dir / f"trivy-image-report-{repeat_id}.json"
        timing_path = reports_dir / f"trivy-timing-{repeat_id}.json"
        if not image_path.is_file() or not timing_path.is_file():
            raise ValueError(
                f"Lần {repeat_no} thiếu báo cáo image hoặc timing JSON."
            )

        fs_total, fs_critical, fs_max = parse_trivy_report(fs_path)
        image_total, image_critical, image_max = parse_trivy_report(image_path)
        timing = read_json(timing_path)
        timing_repeat = timing.get("repeat_no")
        if timing_repeat != repeat_no:
            raise ValueError(f"Repeat_No trong timing không khớp file lần {repeat_no}")

        version = timing.get("trivy_version")
        db_warmed_at = timing.get("vulnerability_db_warmed_at_utc")
        if not isinstance(version, str) or not version.strip():
            raise ValueError(f"Timing lần {repeat_no} thiếu phiên bản Trivy")
        if not isinstance(db_warmed_at, str) or not db_warmed_at.strip():
            raise ValueError(f"Timing lần {repeat_no} thiếu thời điểm nạp DB")

        scan_rows = [
            (
                "Trivy (FS)",
                timing.get("trivy_fs_execution_time_sec"),
                fs_total,
                fs_critical,
                fs_max,
                timing.get("trivy_fs_gate_exit_code"),
                "Filesystem vulnerability scan; Raw_Findings gồm mọi severity. "
                "Pipeline_Total_Sec là tổng chu kỳ Trivy FS+Image, không gồm build/deploy.",
            ),
            (
                "Trivy (Image)",
                timing.get("trivy_image_execution_time_sec"),
                image_total,
                image_critical,
                image_max,
                timing.get("trivy_image_gate_exit_code"),
                "Docker image vulnerability scan; Raw_Findings gồm mọi severity. "
                "Pipeline_Total_Sec là tổng chu kỳ Trivy FS+Image, không gồm build/deploy.",
            ),
        ]

        total_time = timing.get("trivy_pipeline_total_sec")
        if not isinstance(total_time, (int, float)) or total_time < 0:
            raise ValueError(f"Tổng thời gian của lần {repeat_no} không hợp lệ")

        rows = []
        for name, duration, total, critical, highest, exit_code, notes in scan_rows:
            if not isinstance(duration, (int, float)) or duration < 0:
                raise ValueError(f"Thời gian {name} lần {repeat_no} không hợp lệ")
            rows.append(
                {
                    "Repeat_No": repeat_no,
                    "Scanner_Name": name,
                    "Scanner_Version": version,
                    "Vulnerability_DB_Warmed_At_UTC": db_warmed_at,
                    "Execution_Time_Sec": f"{duration:.3f}",
                    # Đây là thời gian của hai lượt quét Trivy trong một chu kỳ,
                    # không gồm cài dependency, build image hoặc các job CI khác.
                    "Pipeline_Total_Sec": f"{total_time:.3f}",
                    "Raw_Findings": total,
                    "Critical_Findings": critical,
                    "True_Positives": "",
                    "False_Positives": "",
                    "Missed_Findings": "",
                    "Max_Severity": highest,
                    "Quality_Gate_Status": gate_status(critical, exit_code),
                    "Notes": notes,
                }
            )
        repeats.extend(rows)
    return repeats


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Tự đọc các báo cáo Trivy lặp lại và nối số liệu vào CSV."
    )
    parser.add_argument("--reports-dir", default="trivy-reports")
    parser.add_argument(
        "--output", default=os.environ.get("OUTPUT_CSV", "results_metrics.csv")
    )
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID"))
    parser.add_argument("--scenario", default="Patched")
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "local"))
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Tạo CSV mới; sao lưu file hiện tại trước khi dùng.",
    )
    args = parser.parse_args()
    run_id = args.run_id or datetime.now(timezone.utc).strftime("local-%Y%m%dT%H%M%SZ")

    try:
        reports_dir = resolve_path(args.reports_dir)
        output_path = resolve_path(args.output)
        rows = load_repeats(reports_dir)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists() and output_path.stat().st_size > 0 and not args.reset:
            with output_path.open("r", newline="", encoding="utf-8-sig") as old_csv:
                existing_headers = next(csv.reader(old_csv), [])
            if existing_headers != HEADERS:
                raise ValueError(
                    f"Header của {output_path} không khớp. "
                    "Sao lưu CSV cũ rồi chạy lần đầu với --reset."
                )

        mode = "w" if args.reset else "a"
        needs_header = args.reset or not output_path.exists() or output_path.stat().st_size == 0
        with output_path.open(mode, newline="", encoding="utf-8-sig") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=HEADERS)
            if needs_header:
                writer.writeheader()
            for row in rows:
                writer.writerow(
                    {
                        "Run_ID": run_id,
                        "Commit_Hash": args.commit,
                        "Test_Scenario": args.scenario,
                        **row,
                    }
                )

        print(f"Đã ghi {len(rows)} dòng từ {len(rows) // 2} lần lặp vào {output_path}")
        for row in rows:
            print(
                f"Repeat {row['Repeat_No']} {row['Scanner_Name']}: "
                f"findings={row['Raw_Findings']}, critical={row['Critical_Findings']}, "
                f"max={row['Max_Severity']}, gate={row['Quality_Gate_Status']}, "
                f"time={row['Execution_Time_Sec']}s"
            )
        return 0
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(f"Lỗi tạo CSV: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
