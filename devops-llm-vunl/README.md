# DevOps LLM VUNL - Vision-LLM 기반 웹 취약점 분석 시스템

## 🎯 프로젝트 개요

이 프로젝트는 Vision-capable LLM을 활용하여 웹 취약점 진단 결과 이미지를 분석하고, 보호동기 이론(PMT) 기반의 구조화된 보고서를 생성하는 시스템입니다.

### 주요 기능
- **이미지 업로드**: 웹 취약점 진단 결과 이미지 업로드
- **Vision-LLM 분석**: Gemini Vision API를 통한 이미지 분석
- **PMT 기반 보고서**: 보호동기 이론에 따른 구조화된 분석 결과
- **데이터베이스 저장**: 분석 결과를 MySQL에 저장
- **API 기반 조회**: RESTful API를 통한 보고서 조회

## 🏗️ 아키텍처

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Frontend│    │  Flask Backend  │    │  Gemini Vision  │
│                 │    │                 │    │      API        │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │VulnUploader │ │    │ │/api/vuln/   │ │    │ │Image Analysis│ │
│ │             │ │    │ │analyze      │ │    │ │             │ │
│ │Image Upload │ │───▶│ │             │ │───▶│ │PMT-based    │ │
│ │             │ │    │ │FormData     │ │    │ │Report       │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │                 │
│ │ReportViewer │ │◀───│ │/api/vuln/   │ │    │                 │
│ │             │ │    │ │report/:id   │ │    │                 │
│ │Card Display │ │    │ │             │ │    │                 │
│ │             │ │    │ │JSON Array   │ │    │                 │
│ └─────────────┘ │    │ └─────────────┘ │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   MySQL RDS     │
                       │                 │
                       │ vuln_reports    │
                       │ table           │
                       │                 │
                       └─────────────────┘
```

## 📋 API 스펙

### POST /api/vuln/analyze
- **Content-Type**: `multipart/form-data`
- **파일 필드**: `file` (이미지 파일)
- **응답**: `{"reportId": "<id>"}`

**요청 예시:**
```bash
curl -X POST http://localhost:5000/api/vuln/analyze \
  -F "file=@vulnerability_scan.png"
```

**응답 예시:**
```json
{
  "reportId": "550e8400-e29b-41d4-a716-446655440000"
}
```

### GET /api/vuln/report/:id
- **경로 파라미터**: `id` (reportId)
- **응답**: JSON 배열(취약점별 보고서)

**요청 예시:**
```bash
curl http://localhost:5000/api/vuln/report/550e8400-e29b-41d4-a716-446655440000
```

**응답 예시:**
```json
[
  {
    "vuln_id": "VULN-001",
    "type": "SQL Injection",
    "incidents": [
      {
        "title": "A사 개인정보 유출 사고",
        "date": "2023-01-15",
        "summary": "SQL Injection 취약점을 악용하여 고객 개인정보 유출"
      }
    ],
    "risk": "공격자가 데이터베이스에 직접 접근하여 데이터 수정/삭제/탈취 가능",
    "management": {
      "urgent": "임시 방편으로 취약한 페이지 접근 차단",
      "short_term": "입력값 검증 강화 및 Prepared Statements 사용",
      "long_term": "정기적인 취약점 점검 및 보안 교육 실시"
    },
    "metacognition": "개발자 보안 인식 제고를 위한 교육 필요"
  }
]
```

### GET /api/vuln/reports
- **쿼리 파라미터**: `limit` (기본값: 10)
- **응답**: 보고서 목록

### DELETE /api/vuln/report/:id
- **경로 파라미터**: `id` (reportId)
- **응답**: `{"message": "보고서가 성공적으로 삭제되었습니다"}`

## 🔧 환경변수

- `GEMINI_API_KEY`: Vision-LLM 호출용 API 키
- `RDS_HOST`: MySQL RDS 호스트
- `RDS_USER`: 데이터베이스 사용자명 (기본값: admin)
- `RDS_PASSWORD`: 데이터베이스 비밀번호
- `RDS_DATABASE`: 데이터베이스명 (기본값: saju)

## 🎯 사용 플로우

1. **웹에서 이미지 업로드**
   - 사용자가 취약점 진단 결과 이미지 선택
   - VulnUploader 컴포넌트에서 파일 처리

2. **`/api/vuln/analyze` 호출 → `reportId` 수신**
   - Flask 백엔드에서 이미지 분석 요청
   - Gemini Vision API를 통한 PMT 기반 분석
   - 분석 결과를 MySQL에 저장
   - 고유 reportId 반환

3. **`/reports/:id` 접속 → 카드 뷰어**
   - ReportViewer 컴포넌트에서 분석 결과 표시
   - 취약점별 카드 형태로 구조화된 정보 제공
   - 유사 사고 사례, 위험성, 대응 방안, 메타인지 교육 정보 포함

## 🗄️ 데이터베이스 스키마

```sql
CREATE TABLE vuln_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    report_id VARCHAR(36) NOT NULL,
    vuln_id VARCHAR(50) NOT NULL,
    type VARCHAR(100) NOT NULL,
    incidents JSON,
    risk TEXT,
    management JSON,
    metacognition TEXT,
    image_filename VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_report_id (report_id),
    INDEX idx_vuln_id (vuln_id),
    INDEX idx_created_at (created_at),
    INDEX idx_type (type)
);
```

## 🚀 배포 방법

1. **Terraform으로 인프라 배포**
   ```bash
   cd terraform
   terraform init -reconfigure
   terraform plan
   terraform apply
   ```

2. **Ansible으로 애플리케이션 배포**
   ```bash
   cd ansible
   ansible-playbook -i inventories/aws_ec2.yml playbook.yml
   ```

3. **환경변수 설정**
   - RDS 연결 정보
   - Gemini API 키

## 📁 프로젝트 구조

```
devops-llm-vunl/
├── ansible/
│   ├── roles/flask/files/
│   │   ├── app.py              # Flask 애플리케이션
│   │   ├── vulnService.py      # 취약점 분석 서비스
│   │   ├── llm_client.py       # LLM 클라이언트
│   │   └── init_db.sql         # 데이터베이스 스키마
│   └── playbook.yml
├── terraform/                   # AWS 인프라 코드
├── src/                        # React 프론트엔드
│   ├── components/
│   │   ├── VulnUploader.jsx    # 이미지 업로드 컴포넌트
│   │   └── ReportViewer.jsx    # 보고서 뷰어 컴포넌트
│   └── App.js                  # 라우팅 설정
├── test_*.py                   # 테스트 스크립트들
├── PROMPT.md                   # LLM 프롬프트 템플릿
└── README.md
```

## 🔍 PMT 기반 분석 프롬프트

Vision-LLM이 분석하는 PMT(보호동기 이론) 관점:

1. **유사 해킹 사고 사례** (2건)
2. **위험성**: 예상 피해 시나리오
3. **경영진 권고**: 즉시/단기/중장기 대응 방안
4. **메타인지 교육**: 필요성 및 주제

## 📝 개발 가이드

### 로컬 개발 환경
```bash
# 가상환경 생성
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt

# 환경변수 설정
export GEMINI_API_KEY=your-key
export RDS_HOST=localhost

# 앱 실행
python app.py
```

### 테스트
```bash
# API 테스트
curl -X POST -F "file=@vuln_image.jpg" http://localhost:5000/api/vuln/analyze
curl http://localhost:5000/api/vuln/report/1
```

## 🔒 보안 고려사항

1. **파일 업로드 검증**: 허용된 이미지 형식만 업로드
2. **파일명 보안**: UUID를 사용한 고유 파일명 생성
3. **API 키 보안**: 환경변수로 관리
4. **DB 연결 보안**: SSL 연결 사용

## 📈 모니터링

- **로그**: Flask 앱 로그
- **메트릭**: API 응답 시간, 오류율
- **알림**: Slack/Email 알림 설정 가능

## 🤝 기여 가이드

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📄 라이선스

MIT License
