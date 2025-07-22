from flask import Flask, request, render_template_string, jsonify
import os, requests, json, pymysql
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime
import markdown2
from vulnService import create_report, get_report, list_reports, delete_report, generate_final_report_md

# 환경변수 로딩
load_dotenv()

# 환경변수는 vulnService.py에서 사용됨

app = Flask(__name__)

# 파일 업로드 설정
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



HTML_FORM = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevOps LLM VUNL - 웹 취약점 분석</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; }
        .upload-form { border: 2px dashed #3498db; padding: 40px; text-align: center; margin: 20px 0; border-radius: 8px; background-color: #ecf0f1; }
        .upload-form input[type="file"] { margin: 20px 0; padding: 10px; width: 300px; }
        .upload-form button { background-color: #3498db; color: white; border: none; padding: 12px 24px; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .upload-form button:disabled { background-color: #bdc3c7; cursor: not-allowed; }
        .loading { text-align: center; padding: 20px; color: #7f8c8d; }
        .report-link { margin-top: 20px; padding: 15px; background-color: #27ae60; color: white; text-decoration: none; border-radius: 4px; display: inline-block; }
        .reports-list { margin-top: 30px; }
        .report-item { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; background-color: #f8f9fa; }
        .api-info { background-color: #e8f4f8; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .api-info h3 { color: #2980b9; margin-top: 0; }
        .api-info code { background-color: #f1f1f1; padding: 2px 4px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 DevOps LLM VUNL</h1>
        <h2 style="text-align: center; color: #e74c3c;">웹 취약점 진단 이미지 분석 시스템</h2>
        
        <div class="upload-form">
            <h3>📸 취약점 스캔 이미지 업로드</h3>
            <form id="uploadForm">
                <input type="file" id="imageFile" accept="image/*" required>
                <br>
                <button type="submit" id="analyzeBtn">🚀 분석 시작</button>
            </form>
            <div id="loading" class="loading" style="display: none;">🔄 분석 중입니다. 잠시만 기다려주세요...</div>
            <div id="result"></div>
        </div>

        <div class="reports-list">
            <h3>📊 최근 분석 보고서</h3>
            <div id="reportsList">로딩 중...</div>
        </div>

        <div class="api-info">
            <h3>🔧 API 정보</h3>
            <p><strong>POST /api/vuln/analyze</strong> - 이미지 업로드 및 분석</p>
            <p><strong>GET /api/vuln/report/:id</strong> - 분석 결과 조회</p>
            <p><strong>GET /api/vuln/reports</strong> - 보고서 목록 조회</p>
            <p><strong>DELETE /api/vuln/report/:id</strong> - 보고서 삭제</p>
        </div>
    </div>

    <script>
        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const fileInput = document.getElementById('imageFile');
            const analyzeBtn = document.getElementById('analyzeBtn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            
            if (!fileInput.files[0]) {
                alert('파일을 선택해주세요.');
                return;
            }
            
            analyzeBtn.disabled = true;
            loading.style.display = 'block';
            result.innerHTML = '';
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            try {
                const response = await fetch('/api/vuln/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    result.innerHTML = `
                        <div class="report-link">
                            <a href="/reports/${data.reportId}" style="color: white; text-decoration: none;">
                                📊 분석 완료! 보고서 보기
                            </a>
                        </div>
                    `;
                    loadReports(); // 보고서 목록 새로고침
                } else {
                    result.innerHTML = `<div style="color: red;">❌ 오류: ${data.error}</div>`;
                }
            } catch (error) {
                result.innerHTML = `<div style="color: red;">❌ 네트워크 오류: ${error.message}</div>`;
            } finally {
                analyzeBtn.disabled = false;
                loading.style.display = 'none';
            }
        });
        
        async function loadReports() {
            try {
                const response = await fetch('/api/vuln/reports?limit=5');
                const data = await response.json();
                
                const reportsList = document.getElementById('reportsList');
                
                if (data.reports && data.reports.length > 0) {
                    reportsList.innerHTML = data.reports.map(report => `
                        <div class="report-item">
                            <strong>📋 보고서 ID:</strong> ${report.report_id}<br>
                            <strong>📁 파일:</strong> ${report.image_filename}<br>
                            <strong>🔍 취약점 수:</strong> ${report.vulnerability_count}<br>
                            <strong>📅 생성일:</strong> ${new Date(report.created_at).toLocaleString()}<br>
                            <a href="/reports/${report.report_id}" style="color: #3498db;">보고서 보기</a>
                        </div>
                    `).join('');
                } else {
                    reportsList.innerHTML = '<p>아직 분석된 보고서가 없습니다.</p>';
                }
            } catch (error) {
                document.getElementById('reportsList').innerHTML = '<p style="color: red;">보고서 목록을 불러올 수 없습니다.</p>';
            }
        }
        
        // 페이지 로드 시 보고서 목록 불러오기
        loadReports();
    </script>
</body>
</html>
"""



@app.route('/api/vuln/analyze', methods=['POST'])
def vuln_analyze():
    """취약점 분석 API 엔드포인트"""
    try:
        # 파일 체크
        if 'file' not in request.files:
            return jsonify({"error": "파일이 없습니다"}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({"error": "파일이 선택되지 않았습니다"}), 400
        
        if not allowed_file(file.filename):
            return jsonify({"error": "지원하지 않는 파일 형식입니다"}), 400
        
        # 새로운 VulnService를 사용하여 보고서 생성
        report_id = create_report(file)
        
        return jsonify({"reportId": report_id}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vuln/report/<report_id>', methods=['GET'])
def get_vuln_report(report_id):
    """취약점 보고서 조회 API 엔드포인트"""
    try:
        # 경로 파라미터에서 report_id 추출
        report_id = request.view_args['report_id']
        
        # VulnService를 사용하여 보고서 조회
        report_items = get_report(report_id)
        
        if not report_items:
            return jsonify({"error": "Report not found"}), 404
        
        # 취약점 항목들만 배열로 반환
        vulnerabilities = report_items.get('vulnerabilities', [])
        
        return jsonify(vulnerabilities), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vuln/reports', methods=['GET'])
def list_vuln_reports():
    """취약점 보고서 목록 조회 API 엔드포인트"""
    try:
        limit = request.args.get('limit', 10, type=int)
        reports = list_reports(limit)
        
        return jsonify({"reports": reports}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vuln/report/<report_id>', methods=['DELETE'])
def delete_vuln_report(report_id):
    """취약점 보고서 삭제 API 엔드포인트"""
    try:
        success = delete_report(report_id)
        
        if not success:
            return jsonify({"error": "보고서 삭제에 실패했습니다"}), 500
        
        return jsonify({"message": "보고서가 성공적으로 삭제되었습니다"}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vuln/report/<report_id>/final', methods=['GET'])
def get_final_report(report_id):
    """최종 보안 취약점 준수 강화 리포트 다운로드 API 엔드포인트"""
    try:
        # 경로 파라미터에서 report_id 추출
        report_id = request.view_args['report_id']
        
        # 대상 시스템 파라미터 (선택사항)
        target_system = request.args.get('target_system', '웹 애플리케이션')
        
        # 최종 보고서 생성
        final_report = generate_final_report_md(report_id, target_system)
        
        # 파일명 생성
        filename = f"security_vulnerability_report_{report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        # 응답 헤더 설정 (파일 다운로드용)
        response = app.response_class(
            response=final_report,
            status=200,
            mimetype='text/markdown'
        )
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/', methods=['GET'])
def home():
    """메인 페이지 - 취약점 진단 시스템"""
    return render_template_string(HTML_FORM)

@app.route('/reports/<report_id>')
def view_report(report_id):
    """취약점 보고서 상세 보기 페이지"""
    try:
        report_items = get_report(report_id)
        
        if not report_items:
            return """
            <div style="text-align: center; padding: 50px;">
                <h2>❌ 보고서를 찾을 수 없습니다</h2>
                <a href="/" style="color: #3498db;">← 메인으로 돌아가기</a>
            </div>
            """
        
        vulnerabilities = report_items.get('vulnerabilities', [])
        
        # 최종 보고서 생성
        target_system = "웹 애플리케이션"
        final_report = generate_final_report_md(report_id, target_system)
        
        # Markdown을 HTML로 변환
        html_content = markdown2.markdown(final_report, extras=['tables', 'fenced-code-blocks', 'code-friendly'])
        
        html = f"""
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>웹 취약점 종합 보고서 - {report_id}</title>
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }}
                .container {{ 
                    max-width: 1200px; 
                    margin: 0 auto; 
                    background: white; 
                    padding: 40px; 
                    border-radius: 15px; 
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                }}
                h1 {{ 
                    color: #2c3e50; 
                    text-align: center; 
                    margin-bottom: 30px; 
                    font-size: 2.5em;
                    text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
                }}
                h2 {{ 
                    color: #34495e; 
                    border-bottom: 3px solid #3498db; 
                    padding-bottom: 15px; 
                    margin-top: 40px; 
                    font-size: 1.8em;
                }}
                h3 {{ 
                    color: #e74c3c; 
                    margin-top: 25px; 
                    background: linear-gradient(90deg, #f8f9fa 0%, #e9ecef 100%);
                    padding: 15px;
                    border-left: 5px solid #e74c3c;
                    border-radius: 0 5px 5px 0;
                }}
                table {{ 
                    width: 100%; 
                    border-collapse: collapse; 
                    margin: 25px 0; 
                    background: white;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }}
                th, td {{ 
                    border: 1px solid #dee2e6; 
                    padding: 15px; 
                    text-align: left; 
                }}
                th {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    color: white; 
                    font-weight: bold;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }}
                tr:nth-child(even) {{ background-color: #f8f9fa; }}
                tr:hover {{ background-color: #e9ecef; }}
                .back-link {{ 
                    text-align: center; 
                    margin-top: 40px; 
                }}
                .back-link a {{ 
                    color: #3498db; 
                    text-decoration: none; 
                    font-weight: bold;
                    padding: 10px 20px;
                    border: 2px solid #3498db;
                    border-radius: 25px;
                    transition: all 0.3s ease;
                }}
                .back-link a:hover {{ 
                    background-color: #3498db; 
                    color: white;
                }}
                .download-link {{ 
                    text-align: center; 
                    margin: 30px 0; 
                }}
                .download-link a {{ 
                    background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%); 
                    color: white; 
                    padding: 15px 30px; 
                    text-decoration: none; 
                    border-radius: 25px; 
                    display: inline-block;
                    font-weight: bold;
                    box-shadow: 0 4px 15px rgba(39, 174, 96, 0.3);
                    transition: all 0.3s ease;
                }}
                .download-link a:hover {{ 
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(39, 174, 96, 0.4);
                }}
                pre {{ 
                    background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); 
                    padding: 20px; 
                    border-radius: 8px; 
                    overflow-x: auto;
                    border-left: 4px solid #3498db;
                }}
                blockquote {{ 
                    border-left: 5px solid #3498db; 
                    padding: 20px; 
                    margin: 20px 0; 
                    background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                    border-radius: 0 8px 8px 0;
                }}
                .report-header {{
                    text-align: center;
                    margin-bottom: 30px;
                    padding: 20px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border-radius: 10px;
                }}
                .report-id {{
                    font-size: 1.2em;
                    opacity: 0.9;
                    margin-top: 10px;
                }}
                ul, ol {{
                    padding-left: 25px;
                }}
                li {{
                    margin: 8px 0;
                    line-height: 1.6;
                }}
                strong {{
                    color: #2c3e50;
                }}
                .section-divider {{
                    height: 2px;
                    background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
                    margin: 30px 0;
                    border-radius: 1px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="report-header">
                    <h1>🔒 웹 취약점 종합 보고서</h1>
                    <div class="report-id">보고서 ID: {report_id}</div>
                </div>
                
                <div class="download-link">
                    <a href="/api/vuln/report/{report_id}/final" target="_blank">📄 Markdown 보고서 다운로드</a>
                </div>
                
                <div class="section-divider"></div>
                
                {html_content}
                
                <div class="back-link">
                    <a href="/">← 메인으로 돌아가기</a>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        return f"""
        <div style="text-align: center; padding: 50px;">
            <h2>❌ 오류가 발생했습니다</h2>
            <p style="color: #e74c3c;">{str(e)}</p>
            <a href="/" style="color: #3498db;">← 메인으로 돌아가기</a>
        </div>
        """
                        table_html += '<tr>'
                        for cell in cells:
                            table_html += f'<td style="border: 1px solid #ddd; padding: 12px; text-align: left;">{cell}</td>'
                        table_html += '</tr>'
                elif in_table and '|' not in line:
                    in_table = False
                    table_html += '</table>'
                    lines[i-1] = table_html
                    table_html = ''
            
            report_html = '\n'.join(lines)
            
            # 리스트 처리
            report_html = report_html.replace('* **', '<li style="margin: 8px 0;"><strong>')
            report_html = report_html.replace('* ', '<li style="margin: 8px 0;">')
            report_html = report_html.replace('\n\n', '</li>')
            
            # 구분선 처리
            report_html = report_html.replace('---', '<hr style="border: none; border-top: 2px solid #3498db; margin: 30px 0;">')
            
            # JSON 코드 블록 처리
            report_html = report_html.replace('```json', '<pre style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #ddd;"><code>')
            report_html = report_html.replace('```', '</code></pre>')
            
            # 일반 텍스트 처리
            report_html = report_html.replace('\n\n', '</p><p style="margin: 15px 0; line-height: 1.6;">')
            report_html = report_html.replace('\n', '<br>')
            
            # 리스트 래핑
            report_html = report_html.replace('<li style="margin: 8px 0;">', '<ul style="margin: 15px 0; padding-left: 20px;"><li style="margin: 8px 0;">')
            report_html = report_html.replace('</li>', '</li></ul>')
            
            # 최종 정리
            report_html = f'<div style="text-align: left; line-height: 1.6;">{report_html}</div>'
            
            html += report_html
        
        html += """
                <div class="back-link">
                    <a href="/">← 메인으로 돌아가기</a>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        return f"""
        <div style="text-align: center; padding: 50px;">
            <h2>❌ 오류가 발생했습니다</h2>
            <p style="color: red;">{str(e)}</p>
            <a href="/" style="color: #3498db;">← 메인으로 돌아가기</a>
        </div>
        """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
