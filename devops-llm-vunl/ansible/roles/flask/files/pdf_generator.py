import os
import uuid
from datetime import datetime
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
from report_generator import generate_final_report
from vulnService import get_report

class PDFGenerator:
    """PDF 보고서 생성 클래스"""
    
    def __init__(self):
        self.pdf_folder = 'pdf_reports'
        if not os.path.exists(self.pdf_folder):
            os.makedirs(self.pdf_folder)
    
    def generate_pdf_report(self, report_id: str) -> str:
        """
        취약점 보고서를 PDF로 생성
        
        Args:
            report_id: 보고서 ID
            
        Returns:
            str: 생성된 PDF 파일 경로
        """
        try:
            # 1. 보고서 데이터 조회
            report_items = get_report(report_id)
            if not report_items:
                raise Exception("보고서를 찾을 수 없습니다.")
            
            vulnerabilities = report_items.get('vulnerabilities', [])
            image_filename = report_items.get('image_filename', 'unknown.jpg')
            website_url = report_items.get('website_url', '')
            
            # 2. HTML 보고서 생성
            html_content = self._generate_html_report(report_id, vulnerabilities, image_filename, website_url)
            
            # 3. PDF 파일명 생성
            pdf_filename = f"vuln_report_{report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path = os.path.join(self.pdf_folder, pdf_filename)
            
            # 4. PDF 생성
            self._create_pdf(html_content, pdf_path)
            
            return pdf_path
            
        except Exception as e:
            raise Exception(f"PDF 생성 실패: {str(e)}")
    
    def _generate_html_report(self, report_id: str, vulnerabilities: list, image_filename: str, website_url: str) -> str:
        """HTML 보고서 생성"""
        # report_generator에서 Markdown 생성
        markdown_content = generate_final_report(
            vuln_list=vulnerabilities,
            target_system="웹 애플리케이션",
            image_filename=image_filename,
            website_url=website_url
        )
        
        # Markdown을 HTML로 변환
        html_content = self._markdown_to_html(markdown_content)
        
        # 완전한 HTML 문서 생성
        full_html = f"""
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>웹 취약점 종합 보고서 - {report_id}</title>
            <style>
                @page {{
                    size: A4;
                    margin: 2cm;
                    @top-center {{
                        content: "웹 취약점 종합 보고서";
                        font-size: 10pt;
                        color: #666;
                    }}
                    @bottom-center {{
                        content: "페이지 " counter(page) " / " counter(pages);
                        font-size: 10pt;
                        color: #666;
                    }}
                }}
                
                body {{
                    font-family: 'Malgun Gothic', '맑은 고딕', Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }}
                
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                    border-bottom: 3px solid #3498db;
                    padding-bottom: 20px;
                }}
                
                h1 {{
                    color: #2c3e50;
                    font-size: 28pt;
                    margin: 0 0 10px 0;
                    font-weight: bold;
                }}
                
                h2 {{
                    color: #34495e;
                    font-size: 18pt;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                    margin-top: 30px;
                    margin-bottom: 20px;
                    page-break-after: avoid;
                }}
                
                h3 {{
                    color: #e74c3c;
                    font-size: 14pt;
                    background: #f8f9fa;
                    padding: 10px;
                    border-left: 4px solid #e74c3c;
                    margin-top: 25px;
                    margin-bottom: 15px;
                    page-break-after: avoid;
                }}
                
                p {{
                    margin: 10px 0;
                    text-align: justify;
                }}
                
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                    page-break-inside: avoid;
                }}
                
                th, td {{
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                    vertical-align: top;
                }}
                
                th {{
                    background-color: #3498db;
                    color: white;
                    font-weight: bold;
                }}
                
                tr:nth-child(even) {{
                    background-color: #f8f9fa;
                }}
                
                .image-container {{
                    text-align: center;
                    margin: 20px 0;
                    padding: 20px;
                    background-color: #f8f9fa;
                    border-radius: 8px;
                    page-break-inside: avoid;
                }}
                
                .image-container img {{
                    max-width: 100%;
                    height: auto;
                    border: 2px solid #3498db;
                    border-radius: 8px;
                }}
                
                .image-caption {{
                    margin-top: 10px;
                    color: #7f8c8d;
                    font-style: italic;
                    font-size: 11pt;
                }}
                
                .risk-high {{
                    color: #e74c3c;
                    font-weight: bold;
                }}
                
                .risk-medium {{
                    color: #f39c12;
                    font-weight: bold;
                }}
                
                .risk-low {{
                    color: #27ae60;
                    font-weight: bold;
                }}
                
                .highlight {{
                    background-color: #fff3cd;
                    padding: 2px 4px;
                    border-radius: 3px;
                }}
                
                ul, ol {{
                    margin: 10px 0;
                    padding-left: 20px;
                }}
                
                li {{
                    margin: 5px 0;
                }}
                
                .page-break {{
                    page-break-before: always;
                }}
                
                .no-break {{
                    page-break-inside: avoid;
                }}
                
                .footer {{
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    font-size: 10pt;
                    color: #666;
                    text-align: center;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 웹 취약점 종합 보고서</h1>
                <p><strong>보고서 ID:</strong> {report_id}</p>
                <p><strong>생성일:</strong> {datetime.now().strftime('%Y년 %m월 %d일 %H:%M')}</p>
            </div>
            
            {html_content}
            
            <div class="footer">
                <p>본 보고서는 AI 기반 취약점 분석 시스템에 의해 자동 생성되었습니다.</p>
                <p>© 2025 DevOps LLM VUNL - 웹 취약점 진단 시스템</p>
            </div>
        </body>
        </html>
        """
        
        return full_html
    
    def _markdown_to_html(self, markdown_content: str) -> str:
        """Markdown을 HTML로 변환"""
        lines = markdown_content.split('\n')
        html_lines = []
        in_table = False
        table_rows = []
        
        for line in lines:
            # 제목 처리
            if line.startswith('# '):
                html_lines.append(f'<h1>{line[2:]}</h1>')
            elif line.startswith('## '):
                html_lines.append(f'<h2>{line[3:]}</h2>')
            elif line.startswith('### '):
                html_lines.append(f'<h3>{line[4:]}</h3>')
            elif line.startswith('---'):
                html_lines.append('<hr>')
            # 이미지 처리
            elif line.startswith('![') and '](' in line:
                import re
                img_match = re.search(r'!\[([^\]]*)\]\(([^)]+)\)', line)
                if img_match:
                    alt_text = img_match.group(1)
                    img_src = img_match.group(2)
                    # 상대 경로를 절대 경로로 변환
                    if img_src.startswith('/uploads/'):
                        img_src = os.path.abspath(img_src[1:])  # /uploads/ 제거하고 절대 경로로
                    
                    html_lines.append(f'''
                    <div class="image-container">
                        <h4>📸 취약점 진단 이미지</h4>
                        <img src="{img_src}" alt="{alt_text}">
                        <p class="image-caption">이미지에서 발견된 취약점들을 AI가 분석하여 본 보고서를 생성했습니다.</p>
                    </div>
                    ''')
                else:
                    html_lines.append(f'<p>{line}</p>')
            # 테이블 처리
            elif line.startswith('|') and '|' in line[1:]:
                if not in_table:
                    in_table = True
                    table_rows = []
                
                cells = [cell.strip() for cell in line.split('|')[1:-1]]
                if all(cell.startswith('-') for cell in cells):
                    continue  # 구분선 건너뛰기
                else:
                    table_rows.append(cells)
            else:
                # 테이블 종료 처리
                if in_table and table_rows:
                    table_html = '<table class="no-break">'
                    for j, row in enumerate(table_rows):
                        if j == 0:  # 헤더
                            th_tags = ''.join([f'<th>{cell}</th>' for cell in row])
                            table_html += f'<tr>{th_tags}</tr>'
                        else:  # 데이터
                            td_tags = ''.join([f'<td>{cell}</td>' for cell in row])
                            table_html += f'<tr>{td_tags}</tr>'
                    table_html += '</table>'
                    html_lines.append(table_html)
                    in_table = False
                    table_rows = []
                
                # 일반 텍스트
                if line.strip():
                    if line.strip().startswith('- ') or line.strip().startswith('* '):
                        html_lines.append(f'<li>{line.strip()[2:]}</li>')
                    else:
                        # 강조 처리
                        line = line.replace('**', '<strong>').replace('**', '</strong>')
                        line = line.replace('*', '<em>').replace('*', '</em>')
                        html_lines.append(f'<p>{line}</p>')
                else:
                    html_lines.append('<br>')
        
        # 마지막 테이블 처리
        if in_table and table_rows:
            table_html = '<table class="no-break">'
            for j, row in enumerate(table_rows):
                if j == 0:
                    th_tags = ''.join([f'<th>{cell}</th>' for cell in row])
                    table_html += f'<tr>{th_tags}</tr>'
                else:
                    td_tags = ''.join([f'<td>{cell}</td>' for cell in row])
                    table_html += f'<tr>{td_tags}</tr>'
            table_html += '</table>'
            html_lines.append(table_html)
        
        return '\n'.join(html_lines)
    
    def _create_pdf(self, html_content: str, pdf_path: str):
        """HTML을 PDF로 변환"""
        try:
            # 폰트 설정
            font_config = FontConfiguration()
            
            # HTML을 PDF로 변환
            HTML(string=html_content).write_pdf(
                pdf_path,
                font_config=font_config
            )
            
        except Exception as e:
            raise Exception(f"PDF 변환 실패: {str(e)}")

# 전역 함수들
def generate_pdf_report(report_id: str) -> str:
    """PDF 보고서 생성 (전역 함수)"""
    generator = PDFGenerator()
    return generator.generate_pdf_report(report_id) 