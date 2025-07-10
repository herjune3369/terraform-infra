# DevOps/DevSecOps 인프라 자동화 및 보안 포트폴리오

## 📋 목차
1. [프로젝트 한눈에 보기](#프로젝트-한눈에-보기)
2. [프로젝트 개요](#프로젝트-개요)
3. [주요 기능 및 아키텍처](#주요-기능-및-아키텍처)
4. [기술 스택 및 도구](#기술-스택-및-도구)
5. [사용법 및 실습 가이드](#사용법-및-실습-가이드)
6. [교육/연구 활용 포인트](#교육연구-활용-포인트)
7. [주요 코드/설정 예시](#주요-코드설정-예시)
8. [프로젝트 결과 및 시연](#프로젝트-결과-및-시연)
9. [라이선스 및 문의](#라이선스-및-문의)

---

## 1. 프로젝트 한눈에 보기

### 프로젝트명
**DevOps/DevSecOps 인프라 자동화 및 보안 실습 포트폴리오**

### 한 줄 요약
클라우드 기반 인프라를 코드로 자동화하고, 실전형 CI/CD 및 보안 자동화(DevSecOps)까지 구현한 교육·연구·실무용 올인원 프로젝트

### 주요 목적
- **실전 DevOps/DevSecOps 역량 증명**: 인프라 자동화, 애플리케이션 배포, 보안 스캔, AI 기반 리포트까지 전 과정을 자동화
- **교육/연구/실습 활용**: 학생, 연구자, 실무자 모두가 따라할 수 있는 실습형 인프라 제공
- **클라우드 실무 경험**: AWS, IaC, CI/CD, 보안 자동화 등 최신 DevOps/DevSecOps 트렌드 반영

### 핵심 성과
- **IaC(Terraform)로 AWS 인프라 자동 구축**
- **Ansible로 애플리케이션 자동 배포 및 환경설정**
- **GitHub Actions 기반 CI/CD 및 보안 자동화 파이프라인**
- **Trivy로 코드/이미지/IaC 보안 스캔, AI 기반 보안 리포트 자동 생성**
- **실제 서비스(Flask) 배포 및 ALB(로드밸런서)로 외부 서비스 제공**
- **교육/연구/실무에 바로 활용 가능한 오픈소스 구조**

### 주요 기술 스택
- **IaC**: Terraform
- **Configuration Management**: Ansible
- **CI/CD**: GitHub Actions
- **보안**: Trivy, AI 리포트
- **클라우드**: AWS (EC2, RDS, ALB 등)
- **애플리케이션**: Python Flask

---

## 2. 프로젝트 개요

### 프로젝트 배경
현대 IT 산업에서는 인프라의 자동화, 지속적 통합/배포(CI/CD), 그리고 보안(DevSecOps)이 필수 역량으로 자리잡고 있습니다. 특히 클라우드 환경에서의 인프라 관리, 자동화된 배포, 실시간 보안 점검은 실무뿐만 아니라 교육·연구 현장에서도 반드시 다루어야 할 핵심 주제입니다.

### 프로젝트 목표
- **실전 DevOps/DevSecOps 파이프라인 구현**
- **교육 및 실습에 최적화된 오픈소스 인프라 제공**
- **보안 내재화(Shift Left) 실천**

### 실제 활용 시나리오
- **대학/교육기관**: DevOps/클라우드/보안 실습 수업, 캡스톤디자인, 프로젝트
- **연구/실험 환경**: 클라우드 기반 실험 인프라 자동화, 보안 취약점 분석 연구
- **실무/기업 환경**: 사내 DevOps/DevSecOps 파이프라인 구축의 레퍼런스

### 프로젝트의 교육적/실무적 가치
- **실전 역량 강화**
- **문제 해결력 및 협업 능력 향상**
- **최신 트렌드 반영**

---

## 3. 주요 기능 및 아키텍처

### 3.1 전체 아키텍처 다이어그램
```mermaid
graph TD
  A[개발자/학생] -->|GitHub Push| B[GitHub Actions]
  B -->|Terraform| C[AWS 인프라 자동 구축]
  C --> D[EC2 (웹서버, Flask)]
  C --> E[RDS (MySQL)]
  C --> F[ALB (로드밸런서)]
  D --> F
  F -->|외부 접속| G[사용자]
  B -->|Ansible| D
  B -->|Trivy 보안 스캔| H[보안 리포트/AI 리포트]
```

### 3.2 폴더별 역할 및 구조
- **terraform/**: AWS 인프라(IaC) 코드
- **devops-1/**: 인프라 자동화 및 애플리케이션 배포 실습용 예제
- **devsecops-2/**: DevSecOps(보안 자동화) 실습용 예제
- **.github/workflows/**: GitHub Actions 워크플로우

### 3.3 주요 자동화 기능
- **IaC 기반 인프라 자동 구축**
- **CI/CD 파이프라인**
- **애플리케이션 자동 배포**
- **보안 자동화(DevSecOps)**
- **실시간 서비스 제공**

### 3.4 워크플로우(자동화 파이프라인) 요약
- **devops-1-workflow.yml**: 인프라 코드 검증 → Terraform 배포 → Ansible 앱 배포 → 상태 알림
- **devsecops-2-workflow.yml**: Trivy 보안 스캔 → AI 보안 리포트 → 인프라 배포 → 보안 앱 배포 → 상태 알림

### 3.5 교육/실무적 강점
- **실제 클라우드 환경과 동일한 구조**
- **학생/연구자/실무자 모두가 실습 가능한 오픈소스 구조**
- **실전 DevOps/DevSecOps 역량을 한 번에 경험**

---

## 4. 기술 스택 및 도구

### 4.1 인프라 및 클라우드
| 구분         | 도구/서비스         | 주요 역할 및 특징                                      |
|--------------|---------------------|------------------------------------------------------|
| 클라우드     | AWS (EC2, RDS, ALB) | 실전형 인프라 환경, 웹서버 이중화, DB 분리, 로드밸런싱 |
| IaC          | Terraform           | 인프라 코드화, 자동 생성/삭제, 재현성 보장            |

### 4.2 자동화 및 배포
| 구분         | 도구/서비스         | 주요 역할 및 특징                                      |
|--------------|---------------------|------------------------------------------------------|
| CI/CD        | GitHub Actions      | 코드 변경 시 자동 빌드, 테스트, 배포, 보안 스캔        |
| 구성관리     | Ansible             | 서버 환경설정, 앱 배포, DB 초기화, 서비스 관리 자동화  |

### 4.3 애플리케이션 및 백엔드
| 구분         | 도구/서비스         | 주요 역할 및 특징                                      |
|--------------|---------------------|------------------------------------------------------|
| 웹 프레임워크| Flask (Python)      | 경량 웹서비스, REST API, DB 연동, 실습/교육에 최적화   |
| DB           | MySQL (RDS)         | 실전형 데이터 저장, 보안 설정, 자동화된 초기화         |

### 4.4 보안 및 DevSecOps
| 구분         | 도구/서비스         | 주요 역할 및 특징                                      |
|--------------|---------------------|------------------------------------------------------|
| 보안 스캔    | Trivy               | 파일시스템, IaC, 컨테이너 이미지 취약점 자동 스캔      |
| AI 리포트    | Python, OpenAI/Gemini| 보안 결과 요약, AI 기반 리포트 자동 생성              |

### 4.5 기타/지원 도구
| 구분         | 도구/서비스         | 주요 역할 및 특징                                      |
|--------------|---------------------|------------------------------------------------------|
| 버전관리     | Git, GitHub         | 협업, 이력 관리, 오픈소스 실습                        |
| OS           | Ubuntu (EC2)        | 실전 서버 환경, 패키지 관리, 보안 설정                |

### 4.6 기술 스택 한눈에 보기
- ![Terraform](https://img.shields.io/badge/Terraform-7B42BC?logo=terraform&logoColor=white)
- ![Ansible](https://img.shields.io/badge/Ansible-EE0000?logo=ansible&logoColor=white)
- ![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)
- ![AWS](https://img.shields.io/badge/AWS-232F3E?logo=amazonaws&logoColor=white)
- ![Flask](https://img.shields.io/badge/Flask-000000?logo=flask&logoColor=white)
- ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
- ![Trivy](https://img.shields.io/badge/Trivy-5B3CC4?logo=trivy&logoColor=white)
- ![MySQL](https://img.shields.io/badge/MySQL-4479A1?logo=mysql&logoColor=white)
- ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?logo=ubuntu&logoColor=white)

---

## 5. 사용법 및 실습 가이드

### 5.1 사전 준비
- AWS/GitHub 계정, Secrets 등록, 로컬 환경 준비

### 5.2 인프라 배포 (Terraform)
```bash
git clone https://github.com/your-username/your-repo.git
cd your-repo/terraform
terraform init
terraform apply -auto-approve
terraform output
```

### 5.3 애플리케이션 배포 (Ansible)
```bash
cd ../devsecops-2/ansible
ansible-playbook -i inventories/aws_ec2.yml playbook.yml
```

### 5.4 CI/CD 및 보안 자동화 (GitHub Actions)
- 코드 푸시/PR 생성 시 워크플로우 자동 실행
- 실행 결과: 인프라 배포, 앱 배포, 보안 스캔, AI 리포트, ALB 응답 테스트 등

### 5.5 서비스 접속 및 결과 확인
- ALB 주소: http://app-lb-359925557.ap-northeast-2.elb.amazonaws.com
- GitHub Actions에서 보안 리포트, 배포 결과 확인

### 5.6 인프라 삭제
```bash
cd terraform
terraform destroy -auto-approve
```

### 5.7 Troubleshooting
- 502 Bad Gateway, Ansible 에러, Terraform apply 실패 등 자주 발생하는 문제와 해결법 안내

---

## 6. 교육/연구 활용 포인트

### 6.1 실습 중심 DevOps/DevSecOps 교육
- 실제 클라우드 환경 기반 실습, 자동화 파이프라인 실습, 보안 내재화 교육

### 6.2 캡스톤디자인/프로젝트 수업 활용
- 팀 프로젝트 기반 실전 과제, 문제 해결력 및 협업 능력 강화

### 6.3 연구/실험 환경 구축
- 클라우드 기반 실험 인프라 자동화, 보안 취약점 분석 및 자동화 연구

### 6.4 산학협력/실무 연계 교육
- 기업 실무 환경과 동일한 구조, 산학협력 프로젝트/인턴십 연계

### 6.5 오픈소스/커뮤니티 기여
- 오픈소스 기반 실습/연구, 커뮤니티/학회 발표 자료로 활용

### 6.6 기대 효과
- 실전 DevOps/DevSecOps 역량 강화, 최신 IT 트렌드 습득, 문제 해결력/협업 능력/실무 적응력 향상

---

## 7. 주요 코드/설정 예시

### 7.1 IaC(Terraform)로 AWS 인프라 자동 구축
```hcl
resource "aws_instance" "web1" {
  ami           = var.ami_id
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public_subnet_a.id
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  tags = { Name = "webserver1" }
}
```

### 7.2 Ansible로 Flask 앱 자동 배포
```yaml
- name: Set up Python virtual environment
  command: python3 -m venv /home/ubuntu/myapp/venv
  args:
    creates: /home/ubuntu/myapp/venv
  become: true

- name: Start Flask app with nohup
  shell: |
    source /home/ubuntu/myapp/venv/bin/activate
    nohup python /home/ubuntu/myapp/app.py > /home/ubuntu/myapp/flask.log 2>&1 &
  args:
    executable: /bin/bash
  become: true
```

### 7.3 GitHub Actions로 CI/CD 및 보안 자동화
```yaml
jobs:
  trivy-fs-scan:
    name: Trivy File System Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v3
      - name: Run Trivy vulnerability scanner (File System)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: 'devsecops-2'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH,MEDIUM,LOW'
```

### 7.4 Flask 애플리케이션 핵심 코드
```python
@app.route('/', methods=['GET', 'POST'])
def home():
    result = ""
    if request.method == 'POST':
        # ... (입력값 처리, Gemini API 호출)
        result = res.json()["candidates"][0]["content"]["parts"][0]["text"]
        save_to_db(name, f"{calendar} {birth}", hour, result)
    return render_template_string(HTML_FORM, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### 7.5 환경변수 자동 생성 템플릿
```jinja
RDS_HOST={{ rds_endpoint }}
RDS_USER=admin
RDS_PASSWORD={{ db_password }}
RDS_DATABASE=saju
GEMINI_API_KEY=AIzaSyB-lFb9w-Uy-sJtw31xlVx8ohnQpzNje4g
```

---

## 8. 프로젝트 결과 및 시연

### 8.1 인프라 및 서비스 배포 결과
- AWS 인프라 자동 구축 (VPC, EC2, RDS, ALB 등)
- ALB 주소: http://app-lb-359925557.ap-northeast-2.elb.amazonaws.com
- 웹서버1: 13.124.75.254, 웹서버2: 43.202.163.234
- RDS 엔드포인트: flask-db.czos9xo3nzg2.ap-northeast-2.rds.amazonaws.com

### 8.2 실제 서비스 접속 화면
- ALB 주소로 접속 시 사주풀이 웹앱 정상 동작 (스크린샷 첨부)

### 8.3 GitHub Actions 워크플로우 실행 결과
- CI/CD 및 보안 자동화 파이프라인 정상 동작 (실행 결과 스크린샷 첨부)

### 8.4 보안 리포트 및 AI 리포트 예시
- Trivy 보안 스캔 결과, AI 기반 보안 리포트 (예시 이미지 첨부)

### 8.5 실습/연구/교육 활용 시연
- 인프라 배포 → 앱 배포 → 보안 스캔 → 서비스 접속 → 리포트 확인까지 전 과정 실습 가능

### 8.6 추가 시연 자료(선택)
- 동영상 시연 링크, 발표 자료(PDF) 등 첨부 가능

---

## 9. 라이선스 및 문의

### 9.1 라이선스
이 프로젝트는 MIT 라이선스를 따릅니다. 누구나 자유롭게 사용, 수정, 배포, 확장할 수 있습니다.

```
MIT License

Copyright (c) 2024 JUN HEO

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```