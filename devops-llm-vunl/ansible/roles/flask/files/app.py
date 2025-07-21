from flask import Flask, request, render_template_string, jsonify
import os, requests, json, pymysql
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime
from vulnService import create_report, get_report, list_reports, delete_report

# 환경변수 로딩
load_dotenv()

RDS_HOST = os.getenv("RDS_HOST")
RDS_USER = os.getenv("RDS_USER", "admin")
RDS_PASSWORD = os.getenv("RDS_PASSWORD", "yourstrongpassword")
RDS_DATABASE = os.getenv("RDS_DATABASE", "saju")

API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyB-lFb9w-Uy-sJtw31xlVx8ohnQpzNje4g")
GEN_URL = f"https://generativelanguage.googleapis.com/v1/models/gemini-2.0-flash:generateContent?key={API_KEY}"

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
<h2>Gemini 사주풀이</h2>
<form method='POST'>
이름: <input name='name'><br>
생일: <input name='birth'><br>
시간 (0~23): <input name='hour'><br>
력 구분:
  <input type='radio' name='calendar' value='양력' checked> 양력
  <input type='radio' name='calendar' value='음력'> 음력
<br>
<input type='submit' value='사주 풀이'>
</form>
<br><a href='/logs'><button>최근 이력 보기</button></a>
<hr>
<pre>{{ result }}</pre>
"""

def save_to_db(name, birth, hour, result):
    conn = pymysql.connect(
        host=RDS_HOST,
        user=RDS_USER,
        password=RDS_PASSWORD,
        database=RDS_DATABASE
    )
    with conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO logs (name, birth, hour, result) VALUES (%s, %s, %s, %s)",
            (name, birth, hour, result)
        )
        conn.commit()
    conn.close()

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

@app.route('/', methods=['GET', 'POST'])
def home():
    result = ""
    if request.method == 'POST':
        name = request.form['name']
        birth = request.form['birth']
        hour = request.form['hour']
        calendar = request.form['calendar']
        prompt = f"{birth} {hour}시에 태어난 {name}의 사주를 {calendar} 기준 한국 전통 방식으로 자세히 풀어줘."

        try:
            headers = {"Content-Type": "application/json"}
            body = {
                "contents": [
                    {
                        "role": "user",
                        "parts": [
                            {"text": prompt}
                        ]
                    }
                ]
            }
            res = requests.post(GEN_URL, headers=headers, data=json.dumps(body))
            res.raise_for_status()
            result = res.json()["candidates"][0]["content"]["parts"][0]["text"]
            save_to_db(name, f"{calendar} {birth}", hour, result)
        except Exception as e:
            result = f"[오류 발생] {str(e)}"
    return render_template_string(HTML_FORM, result=result)

@app.route('/logs')
def logs():
    conn = pymysql.connect(
        host=RDS_HOST,
        user=RDS_USER,
        password=RDS_PASSWORD,
        database=RDS_DATABASE
    )
    with conn.cursor() as cursor:
        cursor.execute("SELECT id, name, birth, hour, created_at FROM logs ORDER BY created_at DESC LIMIT 10")
        rows = cursor.fetchall()
    conn.close()

    table = "<h2>최근 사주 풀이 이력</h2><ul>"
    for r in rows:
        table += f"<li><a href='/logs/{r[0]}'>{r[1]} ({r[2]} {r[3]}시) - {r[4]}</a></li>"
    table += "</ul><br><a href='/'><button>← 돌아가기</button></a>"
    return table

@app.route('/logs/<int:log_id>')
def log_detail(log_id):
    conn = pymysql.connect(
        host=RDS_HOST,
        user=RDS_USER,
        password=RDS_PASSWORD,
        database=RDS_DATABASE
    )
    with conn.cursor() as cursor:
        cursor.execute("SELECT name, birth, hour, result, created_at FROM logs WHERE id = %s", (log_id,))
        row = cursor.fetchone()
    conn.close()

    if not row:
        return "<h3>기록을 찾을 수 없습니다.</h3><a href='/logs'>← 목록으로</a>"

    return f"""
    <h2>{row[0]}님의 사주 풀이</h2>
    <p><b>생일:</b> {row[1]}</p>
    <p><b>시간:</b> {row[2]}</p>
    <p><b>일시:</b> {row[4]}</p>
    <hr>
    <pre>{row[3]}</pre>
    <br><a href='/logs'><button>← 목록으로</button></a>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
