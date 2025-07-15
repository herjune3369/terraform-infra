# DevSecOps Trivy Security Scanner

이 프로젝트는 Trivy를 사용하여 컨테이너 이미지와 파일시스템의 보안 취약점을 스캔하고, 자동화된 보안 리포트를 생성하는 DevSecOps 도구입니다.

## 🚀 기능

- Trivy를 사용한 컨테이너 이미지 보안 스캔
- 파일시스템 보안 취약점 분석
- 자동화된 보안 리포트 생성 (JSON/테이블 형식)
- Ansible을 통한 자동화된 배포
- Terraform을 통한 인프라 관리
- GitHub Actions를 통한 CI/CD 자동화
- GitHub Security 탭과의 자동 통합

## 📋 사전 요구사항

- Python 3.7+
- Docker
- Trivy
- Ansible
- Terraform
- AWS CLI (AWS 사용 시)

## 🛠️ 설치 및 실행

### 1. 의존성 설치

```bash
# Python 의존성 설치
pip install -r requirements.txt

# Trivy 설치 (macOS)
brew install trivy

# Trivy 설치 (Linux)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

### 2. 환경 설정

```bash
# AWS 자격 증명 설정 (AWS 사용 시)
aws configure

# Terraform 초기화
cd terraform
terraform init
```

### 3. GitHub Secrets 설정

GitHub 저장소의 Settings > Secrets and variables > Actions에서 다음 시크릿을 설정하세요:

- `AWS_ACCESS_KEY_ID`: AWS 액세스 키
- `AWS_SECRET_ACCESS_KEY`: AWS 시크릿 키

## 🚀 자동화된 보안 스캔

### GitHub Actions를 통한 자동 스캔

이 프로젝트는 GitHub Actions를 통해 자동화된 보안 스캔 파이프라인을 제공합니다:

1. **코드 푸시 시 자동 실행**: `main` 또는 `develop` 브랜치에 푸시하면 자동으로 실행됩니다
2. **수동 실행**: GitHub Actions 탭에서 수동으로 워크플로우를 실행할 수 있습니다
3. **스캔 타입 선택**: 이미지 스캔, 코드 스캔, 전체 스캔 중 선택할 수 있습니다

### 워크플로우 단계

1. **Security Scan**: Trivy를 통한 보안 취약점 스캔
2. **Validate Infrastructure**: Terraform 코드 검증
3. **Deploy Infrastructure**: AWS 인프라 배포
4. **Deploy Application**: 보안 스캐너 애플리케이션 배포
5. **Generate Report**: 최종 보안 리포트 생성
6. **Notify**: 스캔 결과 알림

## 🔧 수동 실행 (로컬)

### 보안 스캔 실행

```bash
# GitHub Actions에서 자동 실행
# 또는 수동으로 Trivy 실행

# 컨테이너 이미지 스캔
trivy image nginx:latest

# 파일시스템 스캔
trivy fs .

# 특정 디렉토리 스캔
trivy fs ./src

# JSON 형식으로 결과 저장
trivy image nginx:latest --format json --output results.json
```

### 인프라 배포

```bash
# Terraform으로 인프라 생성
cd terraform
terraform plan
terraform apply

# Ansible으로 애플리케이션 배포
cd ../ansible
ansible-playbook -i inventories/aws_ec2.yml playbook.yml
```

## 📁 프로젝트 구조

```
devsecops_llm/
├── terraform/                 # Terraform 설정
│   ├── main.tf               # AWS 인프라 정의
│   ├── variables.tf          # 변수 정의
│   └── outputs.tf            # 출력 값
├── ansible/                   # Ansible 플레이북
│   ├── playbook.yml          # 배포 플레이북
│   ├── inventories/          # 인벤토리 파일
│   └── roles/                # Ansible 역할
├── README.md                  # 프로젝트 문서
├── SECURITY.md                # 보안 정책
└── .trivyignore              # Trivy 제외 파일 목록
```

## 🔧 사용법

### Trivy 보안 스캔 옵션

```bash
# 컨테이너 이미지 스캔
trivy image nginx:latest
trivy image nginx:latest --format json --output image-results.json

# 파일시스템 스캔
trivy fs .
trivy fs ./src --format table --output fs-results.txt

# 전체 스캔 (현재 디렉토리)
trivy fs . --format json --output comprehensive-results.json

# 특정 취약점 타입만 스캔
trivy image nginx:latest --severity HIGH,CRITICAL
```

### Ansible 배포

```bash
# 개발 환경 배포
ansible-playbook -i inventories/aws_ec2.yml playbook.yml -e "env=dev"

# 프로덕션 환경 배포
ansible-playbook -i inventories/aws_ec2.yml playbook.yml -e "env=prod"
```

## 📊 결과 예시

스캔 결과는 다음과 같은 형식으로 생성됩니다:

### JSON 형식 (GitHub Security 탭용)
```json
{
  "Results": [
    {
      "Target": "nginx:latest",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-1234",
          "Severity": "HIGH",
          "Description": "Security vulnerability description"
        }
      ]
    }
  ]
}
```

### 테이블 형식 (읽기 쉬운 리포트)
```
nginx:latest (debian 11.7)
Total: 15 (UNKNOWN: 0, LOW: 5, MEDIUM: 8, HIGH: 2, CRITICAL: 0)
```

### Markdown 형식 (요약 리포트)
- 발견된 취약점 목록
- 심각도별 분류
- 자동 생성된 요약 리포트

## 📊 모니터링

### GitHub Actions에서 확인

1. GitHub 저장소의 Actions 탭에서 워크플로우 실행 상태를 확인할 수 있습니다
2. 각 단계별 상세 로그를 확인할 수 있습니다
3. 보안 스캔 결과는 Security 탭에서 확인할 수 있습니다
4. 생성된 보안 리포트는 Artifacts에서 다운로드할 수 있습니다

### Trivy 스캔 결과 확인

```bash
# GitHub Actions Artifacts에서 다운로드
# 또는 로컬에서 직접 Trivy 실행

# JSON 형식 결과 확인
cat trivy-*-results.json

# 테이블 형식 결과 확인
cat trivy-*-report.txt

# 요약 리포트 확인
cat trivy-summary-report.md
```

## 🔒 보안 고려사항

- 모든 스캔은 격리된 환경에서 실행됩니다
- 민감한 정보는 환경 변수나 AWS Secrets Manager를 통해 관리됩니다
- 정기적인 보안 업데이트 및 취약점 스캔을 수행합니다
- 모든 배포는 HTTPS를 통해 안전하게 이루어집니다

## 🧹 정리

### 인프라 삭제

```bash
cd terraform
terraform destroy
```

### 로컬 파일 정리

```bash
# Terraform 상태 파일 삭제
rm -rf .terraform
rm -f .terraform.lock.hcl

# 스캔 결과 파일 정리
rm -f trivy-security-report.md
rm -f trivy-results.json
```

## 🤝 기여하기

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 📞 지원

문제가 발생하거나 질문이 있으시면 이슈를 생성해 주세요. # DevSecOps-2 Test
