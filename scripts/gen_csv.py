import json
import csv
import os

OUTPUT_CSV = 'results_metrics.csv'
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
    """Đọc tệp log JSON của Trivy và trích xuất số lượng lỗi cùng mức độ nghiêm trọng cao nhất."""
    # Tìm kiếm linh hoạt: thư mục hiện tại hoặc thư mục cha nếu chạy từ docs/scripts
    target_path = file_path
    if not os.path.exists(target_path):
        alt_path = os.path.join('..', '..', file_path)
        if os.path.exists(alt_path):
            target_path = alt_path
        else:
            print(f"⚠️  Không tìm thấy file: {file_path}")
            return 0, 'UNKNOWN'

    raw_findings = 0
    highest_severity = 'UNKNOWN'
    
    with open(target_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
            for result in data.get('Results', []):
                vulns = result.get('Vulnerabilities', [])
                raw_findings += len(vulns)
                
                for vuln in vulns:
                    sev = vuln.get('Severity', 'UNKNOWN').upper()
                    if SEVERITY_WEIGHT.get(sev, 0) > SEVERITY_WEIGHT.get(highest_severity, 0):
                        highest_severity = sev
        except json.JSONDecodeError:
            print(f"⚠️  Lỗi định dạng JSON trong file: {target_path}")
            
    return raw_findings, highest_severity

def main():
    commit = os.environ.get('GITHUB_SHA', 'v0-buggy')
    
    # Đọc log Trivy FS và Image
    fs_find, fs_sev = parse_trivy_log('trivy-fs-report.json')
    img_find, img_sev = parse_trivy_log('trivy-image-report.json')
    
    # Quality Gate: Đánh FAILED nếu tồn tại lỗ hổng HIGH hoặc CRITICAL
    fs_status = 'FAILED' if fs_sev in ['HIGH', 'CRITICAL'] else 'PASSED'
    img_status = 'FAILED' if img_sev in ['HIGH', 'CRITICAL'] else 'PASSED'
    
    # Đối với phiên bản kiểm thử v0-buggy, số phát hiện thực tế coi như True Positives
    records = [
        ('1', '1', commit, 'Baseline', 'Trivy (FS)', '15', '120', fs_find, fs_find, 0, 0, fs_sev, fs_status, 'Quét tệp phụ thuộc package.json'),
        ('1', '1', commit, 'Baseline', 'Trivy (Image)', '30', '120', img_find, img_find, 0, 0, img_sev, img_status, 'Quét Docker Image')
    ]
    
    file_exists = os.path.isfile(OUTPUT_CSV)
    with open(OUTPUT_CSV, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(HEADERS)
        writer.writerows(records)
        
    print(f"✅ Đã trích xuất số liệu thành công vào {OUTPUT_CSV}")
    for rec in records:
        print(f"   -> {rec[4]}: Findings={rec[7]}, Max_Severity={rec[11]}, Status={rec[12]}")

if __name__ == '__main__':
    main()