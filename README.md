# 🚀 Cloud Security Portfolio

<div align="center">

![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-7B42BC?style=for-the-badge&logo=terraform&logoColor=white)
![Ansible](https://img.shields.io/badge/Ansible-EE0000?style=for-the-badge&logo=ansible&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

**DevOps & DevSecOps 자동화 포트폴리오**

[![DevOps Workflow](https://github.com/herjune3369/terraform-infra/workflows/DevOps%20Infrastructure%20Automation/badge.svg)](https://github.com/herjune3369/terraform-infra/actions/workflows/1.%20devops-workflow.yml)
[![DevSecOps Workflow](https://github.com/herjune3369/terraform-infra/workflows/DevSecOps%20Security%20Scanner/badge.svg)](https://github.com/herjune3369/terraform-infra/actions/workflows/2.%20devsecops_llm-workflow.yml)

</div>

---

## 📋 프로젝트 개요

이 포트폴리오는 **DevOps**와 **DevSecOps** 자동화 기술을 보여주는 실전 프로젝트들을 포함합니다. 각 프로젝트는 GitHub Actions를 통해 완전 자동화되어 있으며, 실제 클라우드 인프라에서 실행됩니다.

### 🎯 주요 특징

- ✅ **완전 자동화**: GitHub Actions 기반 CI/CD 파이프라인
- ✅ **실전 프로젝트**: 실제 AWS 인프라 배포 및 관리
- ✅ **보안 중심**: Trivy를 통한 자동 보안 스캔
- ✅ **인프라 코드**: Terraform을 통한 Infrastructure as Code
- ✅ **배포 자동화**: Ansible을 통한 애플리케이션 배포
- ✅ **멀티 환경**: 개발/스테이징/프로덕션 환경 지원

---

## 🚀 프로젝트 1: DevOps Infrastructure Automation

### 📊 프로젝트 정보
- **목적**: AWS 인프라 자동화 및 Flask 애플리케이션 배포
- **기술 스택**: Terraform, Ansible, AWS, Flask, GitHub Actions
- **상태**: ![DevOps Workflow](https://github.com/herjune3369/terraform-infra/workflows/DevOps%20Infrastructure%20Automation/badge.svg)

### 🛠️ 주요 기능
- 🏗️ **Terraform 인프라 자동화**: VPC, EC2, 보안그룹 자동 생성
- 🚀 **Ansible 배포 자동화**: Flask 애플리케이션 자동 배포
- 🔄 **CI/CD 파이프라인**: GitHub Actions 기반 완전 자동화
- 🌍 **멀티 환경 지원**: dev/staging/prod 환경 분리
- 🔒 **보안 스캔**: Trivy를 통한 취약점 자동 검사

### 📁 프로젝트 구조
```
1. devops/
├── terraform/          # Infrastructure as Code
│   ├── main.tf        # AWS 리소스 정의
│   ├── variables.tf   # 변수 정의
│   └── outputs.tf     # 출력 값
├── ansible/           # Configuration Management
│   ├── playbook.yml   # 배포 플레이북
│   └── roles/         # Ansible 역할
└── README.md          # 프로젝트 문서
```

### 🎮 실행 방법
1. **GitHub Actions에서 실행**:
   - [Actions 탭](https://github.com/herjune3369/terraform-infra/actions) → DevOps Infrastructure Automation → Run workflow
2. **환경 선택**: dev/staging/prod
3. **실행 확인**: Actions 탭에서 실시간 모니터링

---

## 🔒 프로젝트 2: DevSecOps Security Scanner

### 📊 프로젝트 정보
- **목적**: 보안 취약점 스캔 및 LLM 기반 보안 리포트 생성
- **기술 스택**: Trivy, Python, Terraform, Ansible, LLM
- **상태**: ![DevSecOps Workflow](https://github.com/herjune3369/terraform-infra/workflows/DevSecOps%20Security%20Scanner/badge.svg)

### 🛠️ 주요 기능
- 🔍 **Trivy 보안 스캔**: 컨테이너 이미지 및 코드 취약점 검사
- 🤖 **LLM 분석**: AI 기반 보안 리포트 자동 생성
- 📊 **보안 리포트**: 상세한 취약점 분석 및 해결책 제시
- 🚀 **자동화된 배포**: 보안 스캐너 인프라 자동 구축
- 📈 **실시간 모니터링**: GitHub Actions 기반 상태 추적

### 📁 프로젝트 구조
```
2. devsecops_llm/
├── generate_security_report.py  # 메인 스캔 스크립트
├── requirements.txt             # Python 의존성
├── terraform/                   # 보안 인프라
├── ansible/                     # 스캐너 배포
└── README.md                    # 프로젝트 문서
```

### 🎮 실행 방법
1. **GitHub Actions에서 실행**:
   - [Actions 탭](https://github.com/herjune3369/terraform-infra/actions) → DevSecOps Security Scanner → Run workflow
2. **스캔 타입 선택**: image/code/full
3. **대상 지정**: 스캔할 이미지나 경로 입력
4. **결과 확인**: Security 탭에서 스캔 결과 확인

---

## 🛠️ 기술 스택

### 🏗️ Infrastructure & DevOps
- **Terraform**: Infrastructure as Code
- **Ansible**: Configuration Management
- **GitHub Actions**: CI/CD Pipeline
- **AWS**: Cloud Infrastructure

### 🔒 Security & Monitoring
- **Trivy**: Vulnerability Scanner
- **Python**: Security Scripting
- **LLM**: AI-powered Analysis

### 🐳 Container & Runtime
- **Docker**: Containerization
- **Flask**: Web Application
- **Linux**: Server Environment

---

## 📈 실시간 상태

### 🔄 워크플로우 상태
- [DevOps Infrastructure Automation](https://github.com/herjune3369/terraform-infra/actions/workflows/1.%20devops-workflow.yml)
- [DevSecOps Security Scanner](https://github.com/herjune3369/terraform-infra/actions/workflows/2.%20devsecops_llm-workflow.yml)

### 🔒 보안 스캔 결과
- [Security Tab](https://github.com/herjune3369/terraform-infra/security)에서 실시간 보안 상태 확인

### 📊 배포 상태
- 각 프로젝트의 Actions 탭에서 실시간 배포 상태 모니터링

---

## 🚀 빠른 시작

### 1. 저장소 클론
```bash
git clone https://github.com/herjune3369/terraform-infra.git
cd terraform-infra
```

### 2. DevOps 프로젝트 실행
```bash
# GitHub Actions에서 수동 실행
# 또는 특정 파일 수정 후 푸시
echo "# Update" >> "1. devops/README.md"
git add "1. devops/"
git commit -m "Trigger DevOps workflow"
git push origin main
```

### 3. DevSecOps 프로젝트 실행
```bash
# GitHub Actions에서 수동 실행
# 또는 특정 파일 수정 후 푸시
echo "# Update" >> "2. devsecops_llm/README.md"
git add "2. devsecops_llm/"
git commit -m "Trigger DevSecOps workflow"
git push origin main
```

---

## 📊 포트폴리오 하이라이트

### 🏆 주요 성과
- ✅ **완전 자동화된 CI/CD 파이프라인 구축**
- ✅ **Infrastructure as Code 실전 적용**
- ✅ **보안 자동화 및 취약점 관리**
- ✅ **멀티 클라우드 환경 지원**
- ✅ **실시간 모니터링 및 알림**

### 🎯 기술적 도전과제 해결
- **복잡한 인프라 자동화**: Terraform + Ansible 조합으로 해결
- **보안 취약점 관리**: Trivy + LLM 조합으로 자동화
- **배포 프로세스 표준화**: GitHub Actions로 완전 자동화
- **환경별 설정 관리**: 변수 기반 환경 분리

---

## 🤝 기여하기

1. **Fork** the Project
2. **Create** your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your Changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the Branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

---

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

---

## 📞 연락처

- **GitHub**: [@herjune3369](https://github.com/herjune3369)
- **Portfolio**: [Cloud Security Portfolio](https://github.com/herjune3369/terraform-infra)

---

<div align="center">

**⭐ 이 저장소가 도움이 되었다면 스타를 눌러주세요! ⭐**

</div> 