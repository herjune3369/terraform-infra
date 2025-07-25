from flask import Flask, request, render_template_string, jsonify
import os, requests, json, pymysql
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime
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
                <div style="margin-bottom: 20px;">
                    <label for="websiteUrl" style="display: block; margin-bottom: 8px; font-weight: bold; color: #2c3e50;">🌐 분석 대상 웹사이트 주소:</label>
                    <input type="url" id="websiteUrl" placeholder="https://example.com" style="width: 100%; padding: 12px; border: 2px solid #3498db; border-radius: 4px; font-size: 16px;" required>
                </div>
                <div style="margin-bottom: 20px;">
                    <label for="imageFile" style="display: block; margin-bottom: 8px; font-weight: bold; color: #2c3e50;">📸 취약점 진단 이미지:</label>
                    <input type="file" id="imageFile" accept="image/*" required style="width: 100%; padding: 12px; border: 2px solid #3498db; border-radius: 4px; font-size: 16px;">
                </div>
                <button type="submit" id="analyzeBtn">🚀 분석 시작</button>
            </form>
            <div id="loading" class="loading" style="display: none;">🔄 분석 중입니다. 잠시만 기다려주세요...</div>
            <div id="result"></div>
        </div>

        <div class="chatbot-section">
            <h3>🤖 AI 보안 챗봇</h3>
            <div style="margin-bottom: 20px;">
                <label for="reportSelect" style="display: block; margin-bottom: 8px; font-weight: bold; color: #2c3e50;">📊 분석할 보고서 선택:</label>
                <select id="reportSelect" style="width: 100%; padding: 10px; border: 2px solid #3498db; border-radius: 4px; font-size: 14px;" onchange="loadChatbot()">
                    <option value="">보고서를 선택하세요</option>
                </select>
            </div>
            
            <div id="chatbotContainer" style="display: none;">
                <div id="chatMessages" style="height: 300px; border: 1px solid #ddd; padding: 15px; overflow-y: auto; background-color: #f8f9fa; border-radius: 5px; margin-bottom: 15px;">
                    <div style="text-align: center; color: #7f8c8d;">챗봇과 대화를 시작하세요! 👋</div>
                </div>
                
                <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                    <input type="text" id="chatInput" placeholder="질문을 입력하세요..." style="flex: 1; padding: 10px; border: 2px solid #3498db; border-radius: 4px; font-size: 14px;">
                    <button onclick="sendMessage()" style="background-color: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer;">전송</button>
                </div>
                
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <button onclick="quickAnalysis()" style="background-color: #e74c3c; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 12px;">🔍 빠른 분석</button>
                    <button onclick="getSecurityTips()" style="background-color: #f39c12; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 12px;">💡 보안 팁</button>
                    <button onclick="clearChat()" style="background-color: #95a5a6; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 12px;">🗑️ 대화 초기화</button>
                </div>
            </div>
        </div>

        <div class="reports-list">
            <h3>📊 최근 분석 보고서</h3>
            <div style="margin-bottom: 20px;">
                <label for="websiteFilter" style="display: block; margin-bottom: 8px; font-weight: bold; color: #2c3e50;">🌐 웹사이트별 필터:</label>
                <select id="websiteFilter" style="width: 100%; padding: 10px; border: 2px solid #3498db; border-radius: 4px; font-size: 14px;" onchange="filterReports()">
                    <option value="">전체 웹사이트</option>
                </select>
            </div>
            <div id="reportsList">로딩 중...</div>
        </div>

        <div class="api-info">
            <h3>🔧 API 정보</h3>
            <p><strong>POST /api/vuln/analyze</strong> - 이미지 업로드 및 분석</p>
            <p><strong>GET /api/vuln/report/:id</strong> - 분석 결과 조회</p>
            <p><strong>GET /api/vuln/reports</strong> - 보고서 목록 조회</p>
            <p><strong>DELETE /api/vuln/report/:id</strong> - 보고서 삭제</p>
            <p><strong>POST /api/chat</strong> - AI 챗봇 대화</p>
            <p><strong>POST /api/chat/quick-analysis</strong> - 빠른 취약점 분석</p>
            <p><strong>GET /api/chat/security-tips</strong> - 보안 팁 제공</p>
        </div>
    </div>

    <script>
        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const websiteUrlInput = document.getElementById('websiteUrl');
            const fileInput = document.getElementById('imageFile');
            const analyzeBtn = document.getElementById('analyzeBtn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            
            if (!websiteUrlInput.value.trim()) {
                alert('웹사이트 주소를 입력해주세요.');
                return;
            }
            
            if (!fileInput.files[0]) {
                alert('파일을 선택해주세요.');
                return;
            }
            
            analyzeBtn.disabled = true;
            loading.style.display = 'block';
            result.innerHTML = '';
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('website_url', websiteUrlInput.value.trim());
            
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
        
        let allReports = [];
        
        async function loadReports() {
            try {
                const response = await fetch('/api/vuln/reports?limit=50');
                const data = await response.json();
                
                if (data.reports && data.reports.length > 0) {
                    allReports = data.reports;
                    updateWebsiteFilter();
                    displayReports(allReports);
                } else {
                    document.getElementById('reportsList').innerHTML = '<p>아직 분석된 보고서가 없습니다.</p>';
                }
            } catch (error) {
                document.getElementById('reportsList').innerHTML = '<p style="color: red;">보고서 목록을 불러올 수 없습니다.</p>';
            }
        }
        
        function updateWebsiteFilter() {
            const websiteFilter = document.getElementById('websiteFilter');
            const websites = [...new Set(allReports.map(report => report.website_url).filter(url => url))];
            
            // 기존 옵션 제거 (전체 웹사이트 제외)
            while (websiteFilter.children.length > 1) {
                websiteFilter.removeChild(websiteFilter.lastChild);
            }
            
            // 웹사이트 옵션 추가
            websites.forEach(website => {
                const option = document.createElement('option');
                option.value = website;
                option.textContent = website;
                websiteFilter.appendChild(option);
            });
        }
        
        function filterReports() {
            const selectedWebsite = document.getElementById('websiteFilter').value;
            const filteredReports = selectedWebsite 
                ? allReports.filter(report => report.website_url === selectedWebsite)
                : allReports;
            
            displayReports(filteredReports);
        }
        
        function displayReports(reports) {
            const reportsList = document.getElementById('reportsList');
            
            if (reports.length > 0) {
                reportsList.innerHTML = reports.map(report => {
                    // 서울 시간으로 변환
                    const seoulTime = new Date(report.created_at).toLocaleString('ko-KR', {
                        timeZone: 'Asia/Seoul',
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit'
                    });
                    
                    return `
                        <div class="report-item">
                            <strong>🌐 웹사이트:</strong> ${report.website_url || 'N/A'}<br>
                            <strong>🔍 취약점 수:</strong> ${report.vulnerability_count}<br>
                            <strong>📅 생성일:</strong> ${seoulTime}<br>
                            <div style="margin-top: 10px;">
                                <a href="/reports/${report.report_id}" style="color: #3498db;">📊 보고서 보기</a>
                            </div>
                        </div>
                    `;
                }).join('');
            } else {
                reportsList.innerHTML = '<p>해당 웹사이트의 분석 보고서가 없습니다.</p>';
            }
        }
        
        // 페이지 로드 시 보고서 목록 불러오기
        loadReports();
        
        // 챗봇 관련 변수
        let currentReportId = null;
        let chatHistory = [];
        
        // 챗봇 초기화
        function loadChatbot() {
            const reportSelect = document.getElementById('reportSelect');
            const chatbotContainer = document.getElementById('chatbotContainer');
            
            if (reportSelect.value) {
                currentReportId = reportSelect.value;
                chatbotContainer.style.display = 'block';
                clearChat();
                addMessage('bot', '안녕하세요! 보안 전문가 챗봇입니다. 취약점 분석에 대해 궁금한 점이 있으시면 언제든 물어보세요! 🔒');
            } else {
                chatbotContainer.style.display = 'none';
                currentReportId = null;
            }
        }
        
        // 메시지 전송
        async function sendMessage() {
            const chatInput = document.getElementById('chatInput');
            const message = chatInput.value.trim();
            
            if (!message || !currentReportId) return;
            
            // 사용자 메시지 추가
            addMessage('user', message);
            chatInput.value = '';
            
            try {
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        report_id: currentReportId,
                        message: message,
                        chat_history: chatHistory
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    addMessage('bot', data.answer);
                    chatHistory.push({user: message, bot: data.answer});
                } else {
                    addMessage('bot', `❌ 오류: ${data.error}`);
                }
            } catch (error) {
                addMessage('bot', `❌ 네트워크 오류: ${error.message}`);
            }
        }
        
        // 메시지 추가
        function addMessage(sender, message) {
            const chatMessages = document.getElementById('chatMessages');
            const messageDiv = document.createElement('div');
            messageDiv.style.marginBottom = '10px';
            messageDiv.style.padding = '8px 12px';
            messageDiv.style.borderRadius = '8px';
            messageDiv.style.maxWidth = '80%';
            
            if (sender === 'user') {
                messageDiv.style.backgroundColor = '#3498db';
                messageDiv.style.color = 'white';
                messageDiv.style.marginLeft = 'auto';
                messageDiv.textContent = message;
            } else {
                messageDiv.style.backgroundColor = '#ecf0f1';
                messageDiv.style.color = '#2c3e50';
                messageDiv.style.marginRight = 'auto';
                messageDiv.innerHTML = message.replace(/\n/g, '<br>');
            }
            
            chatMessages.appendChild(messageDiv);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
        
        // 빠른 분석
        async function quickAnalysis() {
            if (!currentReportId) {
                alert('먼저 보고서를 선택해주세요.');
                return;
            }
            
            try {
                const response = await fetch('/api/chat/quick-analysis', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        report_id: currentReportId
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    addMessage('bot', data.analysis);
                } else {
                    addMessage('bot', `❌ 오류: ${data.error}`);
                }
            } catch (error) {
                addMessage('bot', `❌ 네트워크 오류: ${error.message}`);
            }
        }
        
        // 보안 팁 가져오기
        async function getSecurityTips() {
            try {
                const response = await fetch('/api/chat/security-tips');
                const data = await response.json();
                
                if (response.ok) {
                    let tipsMessage = '💡 **보안 팁 모음**\n\n';
                    data.tips.forEach((tip, index) => {
                        tipsMessage += `${index + 1}. **${tip.category}**: ${tip.tip}\n   ${tip.description}\n\n`;
                    });
                    addMessage('bot', tipsMessage);
                } else {
                    addMessage('bot', `❌ 오류: ${data.error}`);
                }
            } catch (error) {
                addMessage('bot', `❌ 네트워크 오류: ${error.message}`);
            }
        }
        
        // 대화 초기화
        function clearChat() {
            const chatMessages = document.getElementById('chatMessages');
            chatMessages.innerHTML = '<div style="text-align: center; color: #7f8c8d;">챗봇과 대화를 시작하세요! 👋</div>';
            chatHistory = [];
        }
        
        // 보고서 목록 로드 시 챗봇 선택 옵션도 업데이트
        function updateReportSelect() {
            const reportSelect = document.getElementById('reportSelect');
            
            // 기존 옵션 제거 (첫 번째 옵션 제외)
            while (reportSelect.children.length > 1) {
                reportSelect.removeChild(reportSelect.lastChild);
            }
            
            // 보고서 옵션 추가
            allReports.forEach(report => {
                const option = document.createElement('option');
                option.value = report.report_id;
                option.textContent = `${report.website_url || 'N/A'} (${report.vulnerability_count}개 취약점)`;
                reportSelect.appendChild(option);
            });
        }
        
        // Enter 키로 메시지 전송
        document.getElementById('chatInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
        
        // 기존 loadReports 함수 수정
        const originalLoadReports = loadReports;
        loadReports = async function() {
            await originalLoadReports();
            updateReportSelect();
        };
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
        
        # 웹사이트 URL 체크
        website_url = request.form.get('website_url', '').strip()
        if not website_url:
            return jsonify({"error": "웹사이트 주소를 입력해주세요"}), 400
        
        # 새로운 VulnService를 사용하여 보고서 생성
        report_id = create_report(file, website_url)
        
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
    """최종 보고서 생성 API 엔드포인트"""
    try:
        report_items = get_report(report_id)
        
        if not report_items:
            return jsonify({"error": "해당 report_id의 보고서를 찾을 수 없습니다."}), 404
        
        vulnerabilities = report_items.get('vulnerabilities', [])
        website_url = report_items.get('website_url', '')
        image_filename = report_items.get('image_filename', '')
        
        # 최종 보고서 생성
        target_system = "웹 애플리케이션"
        final_report = generate_final_report_md(
            vuln_list=vulnerabilities,
            target_system=target_system,
            image_filename=image_filename,
            website_url=website_url
        )
        
        return final_report, 200, {'Content-Type': 'text/markdown; charset=utf-8'}
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat_with_report():
    """고급 챗봇: LLM을 활용한 대화형 취약점 분석 도우미"""
    try:
        data = request.get_json()
        report_id = data.get('report_id')
        message = data.get('message')
        chat_history = data.get('chat_history', [])
        
        if not report_id or not message:
            return jsonify({'error': 'report_id와 message가 필요합니다.'}), 400
        
        # 보고서 내용 불러오기
        report_items = get_report(report_id)
        if not report_items:
            return jsonify({'error': '해당 report_id의 보고서를 찾을 수 없습니다.'}), 404
        
        # 보고서 정보 추출
        vulnerabilities = report_items.get('vulnerabilities', [])
        website_url = report_items.get('website_url', '')
        image_filename = report_items.get('image_filename', '')
        
        # LLM 클라이언트 초기화
        try:
            from llm_client import LLMClient
            llm_client = LLMClient()
            
            # 대화 컨텍스트 구성
            context = f"""
보안 취약점 분석 보고서 정보:
- 웹사이트: {website_url}
- 이미지 파일: {image_filename}
- 발견된 취약점 수: {len(vulnerabilities)}

취약점 목록:
"""
            
            for i, vuln in enumerate(vulnerabilities, 1):
                context += f"{i}. {vuln.get('type', '알 수 없음')}: {vuln.get('summary', '설명 없음')}\n"
            
            # 대화 히스토리 구성
            conversation_history = ""
            if chat_history:
                conversation_history = "\n".join([f"사용자: {msg.get('user', '')}\n챗봇: {msg.get('bot', '')}" for msg in chat_history[-5:]])  # 최근 5개만
            
            # 프롬프트 구성
            prompt = f"""
당신은 보안 전문가 챗봇입니다. 사용자의 질문에 대해 친근하고 전문적으로 답변해주세요.

{context}

이전 대화:
{conversation_history}

사용자 질문: {message}

다음 중 하나의 역할로 답변해주세요:
1. 보안 컨설턴트: 취약점에 대한 전문적인 조언 제공
2. 교육자: 보안 개념을 쉽게 설명
3. 문제 해결사: 구체적인 해결 방안 제시
4. 친구: 격려와 동기부여 제공

답변은 한국어로 하고, 이모지를 적절히 사용하여 친근하게 만들어주세요.
"""
            
            # LLM 호출
            response = llm_client.generate_response(prompt)
            
            return jsonify({
                'answer': response,
                'status': 'success',
                'report_summary': f"웹사이트: {website_url}\n취약점 수: {len(vulnerabilities)}개",
                'vulnerability_count': len(vulnerabilities),
                'chat_type': 'llm_enhanced'
            })
            
        except ImportError:
            # LLM 클라이언트가 없을 경우 기본 응답
            return jsonify({
                'answer': f'안녕하세요! {website_url}의 취약점 분석을 도와드릴게요. {len(vulnerabilities)}개의 취약점이 발견되었습니다. 어떤 것이 궁금하신가요?',
                'status': 'basic_response',
                'report_summary': f"웹사이트: {website_url}\n취약점 수: {len(vulnerabilities)}개",
                'vulnerability_count': len(vulnerabilities),
                'chat_type': 'basic'
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat/quick-analysis', methods=['POST'])
def quick_analysis():
    """빠른 취약점 분석 및 권장사항"""
    try:
        data = request.get_json()
        report_id = data.get('report_id')
        
        if not report_id:
            return jsonify({'error': 'report_id가 필요합니다.'}), 400
        
        # 보고서 내용 불러오기
        report_items = get_report(report_id)
        if not report_items:
            return jsonify({'error': '해당 report_id의 보고서를 찾을 수 없습니다.'}), 404
        
        vulnerabilities = report_items.get('vulnerabilities', [])
        website_url = report_items.get('website_url', '')
        
        # 취약점 분석
        high_risk = [v for v in vulnerabilities if '높음' in str(v.get('severity', ''))]
        medium_risk = [v for v in vulnerabilities if '중간' in str(v.get('severity', ''))]
        low_risk = [v for v in vulnerabilities if '낮음' in str(v.get('severity', ''))]
        
        # 분석 결과 생성
        analysis = f"""
🔍 **빠른 취약점 분석 결과**

🌐 대상 웹사이트: {website_url}
📊 총 취약점: {len(vulnerabilities)}개

🚨 **위험도별 분류:**
- 🔴 높은 위험: {len(high_risk)}개
- 🟡 중간 위험: {len(medium_risk)}개  
- 🟢 낮은 위험: {len(low_risk)}개

💡 **즉시 조치 권장사항:**
"""
        
        if high_risk:
            analysis += "- 🔴 높은 위험 취약점을 우선적으로 해결하세요\n"
        if medium_risk:
            analysis += "- 🟡 중간 위험 취약점을 단기 내에 해결하세요\n"
        
        analysis += "- 🔧 정기적인 보안 점검을 실시하세요\n"
        analysis += "- 📚 보안 인식 교육을 강화하세요\n"
        
        return jsonify({
            'analysis': analysis,
            'high_risk_count': len(high_risk),
            'medium_risk_count': len(medium_risk),
            'low_risk_count': len(low_risk),
            'total_count': len(vulnerabilities)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat/security-tips', methods=['GET'])
def security_tips():
    """보안 팁 제공"""
    tips = [
        {
            "category": "웹 보안",
            "tip": "모든 사용자 입력을 검증하고 필터링하세요",
            "description": "XSS, SQL Injection 등의 공격을 방지할 수 있습니다"
        },
        {
            "category": "인증",
            "tip": "강력한 비밀번호 정책을 적용하세요",
            "description": "최소 8자, 특수문자 포함, 정기적 변경"
        },
        {
            "category": "파일 업로드",
            "tip": "파일 업로드 시 확장자와 내용을 검증하세요",
            "description": "악성 파일 업로드로 인한 보안 위험을 방지합니다"
        },
        {
            "category": "정보 보호",
            "tip": "민감한 정보를 로그에 기록하지 마세요",
            "description": "개인정보, 비밀번호 등이 노출되지 않도록 주의"
        },
        {
            "category": "업데이트",
            "tip": "정기적으로 보안 패치를 적용하세요",
            "description": "알려진 취약점을 해결하여 공격 위험을 줄입니다"
        }
    ]
    
    return jsonify({
        'tips': tips,
        'total_tips': len(tips)
    })

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """업로드된 이미지 파일을 웹에서 볼 수 있도록 제공"""
    try:
        from flask import send_from_directory
        return send_from_directory('uploads', filename)
    except Exception as e:
        return jsonify({"error": f"이미지를 찾을 수 없습니다: {str(e)}"}), 404



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
        
        # 최종 보고서 생성 (이미지 파일명 포함)
        target_system = "웹 애플리케이션"
        image_filename = report_items.get('image_filename', 'unknown.jpg')
        website_url = report_items.get('website_url', '')
        
        # report_generator를 직접 호출하여 이미지 파일명 전달
        from report_generator import generate_final_report
        final_report = generate_final_report(
            vuln_list=vulnerabilities,
            target_system=target_system,
            image_filename=image_filename,
            website_url=website_url
        )
        
        # Markdown을 간단한 HTML로 변환
        html_content = final_report
        
        # 제목 처리 (정확한 패턴 매칭)
        import re
        
        # 제목 처리 (줄 단위로 처리)
        lines = html_content.split('\n')
        processed_lines = []
        in_table = False
        table_rows = []
        
        for i, line in enumerate(lines):
            if line.startswith('# '):
                processed_lines.append(f'<h1>{line[2:]}</h1>')
            elif line.startswith('## '):
                processed_lines.append(f'<h2>{line[3:]}</h2>')
            elif line.startswith('### '):
                processed_lines.append(f'<h3>{line[4:]}</h3>')
            elif line.startswith('---'):
                processed_lines.append('<hr>')

            elif line.startswith('![') and '](' in line:
                # Markdown 이미지 태그를 HTML로 변환 - 실제 업로드된 이미지 표시
                import re
                img_match = re.search(r'!\[([^\]]*)\]\(([^)]+)\)', line)
                if img_match:
                    alt_text = img_match.group(1)
                    img_src = img_match.group(2)
                    
                    # 간단한 이미지 경로 처리
                    if not img_src.startswith('/uploads/'):
                        img_src = f'/uploads/{img_src}'
                    
                    processed_lines.append(f'''
                    <div style="text-align: center; margin: 20px 0; padding: 20px; background-color: #f8f9fa; border-radius: 8px;">
                        <h4 style="color: #2c3e50; margin-bottom: 15px;">📸 취약점 진단 이미지</h4>
                        <img src="{img_src}" alt="{alt_text}" style="max-width: 100%; height: auto; border: 2px solid #3498db; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" onerror="console.log('이미지 로드 실패:', this.src); this.style.display='none'; this.nextElementSibling.style.display='block';">
                        <p style="margin-top: 10px; color: #e74c3c; font-style: italic; display: none;">⚠️ 이미지를 불러올 수 없습니다: {img_src}</p>
                        <p style="margin-top: 10px; color: #7f8c8d; font-style: italic;">이미지에서 발견된 취약점들을 AI가 분석하여 본 보고서를 생성했습니다.</p>
                        <p style="margin-top: 5px; color: #95a5a6; font-size: 12px;">이미지 경로: {img_src}</p>
                    </div>
                    ''')
                else:
                    processed_lines.append(f'<p>{line}</p>')
            elif line.startswith('|') and '|' in line[1:]:
                # 테이블 행 처리
                if not in_table:
                    in_table = True
                    table_rows = []
                
                cells = [cell.strip() for cell in line.split('|')[1:-1]]
                if all(cell.startswith('-') for cell in cells):
                    # 구분선 행은 건너뛰기
                    continue
                else:
                    # 테이블 행 추가
                    table_rows.append(cells)
            else:
                # 테이블 종료 처리
                if in_table and table_rows:
                    # 테이블 HTML 생성
                    table_html = '<table>'
                    for j, row in enumerate(table_rows):
                        if j == 0:  # 첫 번째 행은 헤더
                            th_tags = ''.join([f'<th>{cell}</th>' for cell in row])
                            table_html += f'<tr>{th_tags}</tr>'
                        else:  # 나머지는 데이터
                            td_tags = ''.join([f'<td>{cell}</td>' for cell in row])
                            table_html += f'<tr>{td_tags}</tr>'
                    table_html += '</table>'
                    processed_lines.append(table_html)
                    in_table = False
                    table_rows = []
                
                # 일반 텍스트
                if line.strip():
                    # 리스트 항목인지 확인
                    if line.strip().startswith('- ') or line.strip().startswith('* '):
                        processed_lines.append(f'<li>{line.strip()[2:]}</li>')
                    else:
                        processed_lines.append(f'<p>{line}</p>')
                else:
                    processed_lines.append('<br>')
        
        # 마지막 테이블 처리
        if in_table and table_rows:
            table_html = '<table>'
            for j, row in enumerate(table_rows):
                if j == 0:  # 첫 번째 행은 헤더
                    th_tags = ''.join([f'<th>{cell}</th>' for cell in row])
                    table_html += f'<tr>{th_tags}</tr>'
                else:  # 나머지는 데이터
                    td_tags = ''.join([f'<td>{cell}</td>' for cell in row])
                    table_html += f'<tr>{td_tags}</tr>'
            table_html += '</table>'
            processed_lines.append(table_html)
        
        html_content = '\n'.join(processed_lines)
        
        # 강조 처리 (이미 처리된 태그 내부는 건드리지 않음)
        html_content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html_content)
        
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
                p {{ 
                    margin: 10px 0; 
                    line-height: 1.6; 
                    color: #333;
                }}
                li {{ 
                    margin: 5px 0; 
                    line-height: 1.5; 
                    color: #333;
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
                    <div class="website-url" style="margin-top: 10px; font-size: 1.1em; opacity: 0.9;">🌐 분석 대상: {website_url if website_url else 'N/A'}</div>
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

if __name__ == '__main__':
    try:
        print("🚀 Flask 애플리케이션 시작 중...")
        print(f"📊 데이터베이스 연결 정보:")
        print(f"   - 호스트: {os.getenv('RDS_HOST', 'N/A')}")
        print(f"   - 데이터베이스: {os.getenv('RDS_DATABASE', 'N/A')}")
        print(f"   - 사용자: {os.getenv('RDS_USER', 'N/A')}")
        print(f"🔑 API 키 상태: {'설정됨' if os.getenv('GEMINI_API_KEY') and os.getenv('GEMINI_API_KEY') != 'your-gemini-api-key-here' else '설정되지 않음'}")
        
        # 데이터베이스 연결 테스트
        try:
            import pymysql
            connection = pymysql.connect(
                host=os.getenv('RDS_HOST'),
                user=os.getenv('RDS_USER'),
                password=os.getenv('RDS_PASSWORD'),
                database=os.getenv('RDS_DATABASE'),
                port=3306
            )
            connection.close()
            print("✅ 데이터베이스 연결 성공")
        except Exception as db_error:
            print(f"❌ 데이터베이스 연결 실패: {db_error}")
        
        print("🌐 Flask 서버 시작...")
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        print(f"❌ Flask 애플리케이션 시작 실패: {e}")
        import traceback
        traceback.print_exc()
