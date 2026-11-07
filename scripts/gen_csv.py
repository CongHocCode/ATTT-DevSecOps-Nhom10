import json
import csv
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_CSV = Path(os.environ.get('OUTPUT_CSV', PROJECT_ROOT / 'results_metrics.csv'))
HEADERS = [
    'Run_ID', 'Repeat_No', 'Commit_Hash', 'Test_Scenario', 'Scanner_Name', 
    'Execution_Time_Sec', 'Pipeline_Total_Sec', 'Raw_Findings', 'True_Positives', 
    'False_Positives', 'Missed_Findings', 'Max_Severity', 'Quality_Gate_Status', 'Notes'
]

SEVERITY_WEIGHT = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'UNKNOWN': 0
}

def parse_trivy_log(file_path):
    """Trả về (số phát hiện, mức cao nhất); None biểu thị báo cáo thiếu/lỗi."""
    target_path = Path(file_path)
    if not target_path.is_absolute():
        target_path = PROJECT_ROOT / target_path
    if not target_path.is_file():
        print(f"[WARN] Missing file: {target_path}")
        return None, 'UNKNOWN'

    raw_findings = 0
    highest_severity = 'UNKNOWN'

    try:
        with target_path.open('r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as error:
        print(f"[WARN] Could not read report {target_path}: {error}")
        return None, 'UNKNOWN'

    if not isinstance(data, dict) or not isinstance(data.get('Results', []), list):
        print(f"[WARN] Invalid Trivy report structure: {target_path}")
        return None, 'UNKNOWN'

    for result in data.get('Results', []):
        vulns = result.get('Vulnerabilities') or []
        if not isinstance(vulns, list):
            print(f"[WARN] Invalid Vulnerabilities list: {target_path}")
            return None, 'UNKNOWN'
        raw_findings += len(vulns)
        for vuln in vulns:
            sev = vuln.get('Severity', 'UNKNOWN').upper()
            if SEVERITY_WEIGHT.get(sev, 0) > SEVERITY_WEIGHT.get(highest_severity, 0):
                highest_severity = sev

    return raw_findings, highest_severity

def main():
    commit = os.environ.get('GITHUB_SHA', 'v0-buggy')
    
    # Đọc log Trivy FS và Image từ thư mục repo, bất kể thư mục gọi lệnh.
    fs_find, fs_sev = parse_trivy_log(os.environ.get('TRIVY_FS_REPORT', 'trivy-fs-report.json'))
    img_find, img_sev = parse_trivy_log(os.environ.get('TRIVY_IMAGE_REPORT', 'trivy-image-report.json'))

    # Báo cáo thiếu/lỗi là INCOMPLETE; báo cáo đầy đủ có HIGH/CRITICAL là FAILED.
    fs_status = quality_gate_status(fs_find, fs_sev)
    img_status = quality_gate_status(img_find, img_sev)

    # Chưa có ground truth nên để trống TP/FP/Missed và thời gian thay vì tự gán số.
    fs_duration = os.environ.get('TRIVY_FS_EXECUTION_TIME_SEC', '')
    img_duration = os.environ.get('TRIVY_IMAGE_EXECUTION_TIME_SEC', '')
    pipeline_duration = os.environ.get('PIPELINE_TOTAL_SEC', '')
    records = [
        ('1', '1', commit, 'Baseline', 'Trivy (FS)', fs_duration, pipeline_duration, fs_find, '', '', '', fs_sev, fs_status, 'Quét phụ thuộc; TP/FP/Missed chưa được đối chiếu ground truth'),
        ('1', '1', commit, 'Baseline', 'Trivy (Image)', img_duration, pipeline_duration, img_find, '', '', '', img_sev, img_status, 'Quét Docker Image; TP/FP/Missed chưa được đối chiếu ground truth')
    ]
    
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    file_exists = OUTPUT_CSV.is_file()
    with OUTPUT_CSV.open('a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(HEADERS)
        writer.writerows(records)
        
    print(f"Metrics written to {OUTPUT_CSV}")
    for rec in records:
        print(f"   {rec[4]}: Findings={rec[7]}, Max_Severity={rec[11]}, Status={rec[12]}")


def quality_gate_status(findings, severity):
    if findings is None:
        return 'INCOMPLETE'
    return 'FAILED' if severity in ['HIGH', 'CRITICAL'] else 'PASSED'

if __name__ == '__main__':
    main()
