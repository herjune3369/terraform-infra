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

# Flask 앱의 HTML 변환 로직 테스트
lines = report.split('\n')
processed_lines = []

for i, line in enumerate(lines):
    if line.startswith('![') and '](' in line:
        # 이미지 태그 처리 - 업로드된 취약점 진단 이미지를 실제로 표시
        import re
        # 더 유연한 정규식 패턴 사용
        img_match = re.search(r'!\[([^\]]*)\]\(([^)]+)\)', line)
        if img_match:
            alt_text = img_match.group(1)
            img_src = img_match.group(2)
            # 이미지를 실제로 표시하는 HTML 태그 생성
            processed_lines.append(f'''
            <div style="text-align: center; margin: 20px 0; padding: 20px; background-color: #f8f9fa; border-radius: 8px;">
                <h4 style="color: #2c3e50; margin-bottom: 15px;">📸 취약점 진단 이미지</h4>
                <img src="{img_src}" alt="{alt_text}" style="max-width: 100%; height: auto; border: 2px solid #3498db; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
                <p style="margin-top: 10px; color: #7f8c8d; font-style: italic;">이미지에서 발견된 취약점들을 AI가 분석하여 본 보고서를 생성했습니다.</p>
            </div>
            ''')
            print(f"DEBUG: 이미지 태그 처리됨 - src: {img_src}, alt: {alt_text}")
        else:
            processed_lines.append(f'<p>{line}</p>')
            print(f"DEBUG: 이미지 태그 매칭 실패 - line: {line}")
    else:
        processed_lines.append(f'<p>{line}</p>')

print("\n=== CONVERTED HTML ===")
for line in processed_lines:
    if 'img src=' in line:
        print(line.strip())
        break 