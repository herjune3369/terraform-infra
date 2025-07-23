#!/usr/bin/env python3

import sys
sys.path.append('ansible/roles/flask/files')

from report_generator import generate_final_report

# 테스트 데이터
test_vulns = [
    {'type': 'SQL Injection', 'risk': '데이터베이스 조작 가능', 'severity': '높음'},
    {'type': 'XSS', 'risk': '스크립트 실행 가능', 'severity': '중간'}
]

# 테스트 보고서 생성
report = generate_final_report(
    vuln_list=test_vulns,
    image_filename='test.png'
)

# 이미지 태그 부분만 출력
print("=== GENERATED MARKDOWN ===")
lines = report.split('\n')
for i, line in enumerate(lines):
    if '![' in line and '](' in line:
        print(f'Line {i+1}: {line}')
        break

print("\n=== FULL REPORT (first 20 lines) ===")
for i, line in enumerate(lines[:20]):
    print(f'{i+1:2d}: {line}') 