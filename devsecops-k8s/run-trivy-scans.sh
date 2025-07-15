#!/bin/bash

# Configuration Layer - Trivy Multi-Scan Script
# 3가지 모드를 순차 실행: IaC, Kubernetes Config, Container Image

set -e

echo "🔍 Configuration Layer - Trivy Multi-Scan 시작"
echo "================================================"

# Trivy 설치 확인
if ! command -v trivy &> /dev/null; then
    echo "❌ Trivy가 설치되지 않았습니다. 설치 중..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.64.1
fi

echo "✅ Trivy 버전: $(trivy --version | head -n1)"

# 결과 디렉토리 생성
mkdir -p trivy-results
cd trivy-results

echo ""
echo "1️⃣ IaC 스캔 (Terraform) 실행 중..."
echo "----------------------------------------"
cd ../terraform
trivy iac --iac-type terraform . --format sarif --output ../trivy-results/trivy-iac-results.sarif --severity CRITICAL,HIGH,MEDIUM,LOW
echo "✅ IaC 스캔 완료: trivy-iac-results.sarif"

echo ""
echo "2️⃣ Kubernetes 매니페스트 스캔 실행 중..."
echo "----------------------------------------"
cd ..

# k8s 매니페스트 디렉토리 생성 (예시)
mkdir -p k8s/manifests

# 샘플 Kubernetes 매니페스트 생성
cat > k8s/manifests/sample-deployment.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sample-app
  labels:
    app: sample-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sample-app
  template:
    metadata:
      labels:
        app: sample-app
    spec:
      containers:
      - name: sample-app
        image: nginx:latest
        ports:
        - containerPort: 80
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
EOF

trivy config k8s/manifests/ --format sarif --output trivy-results/trivy-config-results.sarif --severity CRITICAL,HIGH,MEDIUM,LOW
echo "✅ Kubernetes Config 스캔 완료: trivy-config-results.sarif"

echo ""
echo "3️⃣ 컨테이너 이미지 스캔 실행 중..."
echo "----------------------------------------"
trivy image nginx:latest --format sarif --output trivy-results/trivy-image-results.sarif --severity CRITICAL,HIGH,MEDIUM,LOW
echo "✅ Container Image 스캔 완료: trivy-image-results.sarif"

echo ""
echo "📊 스캔 결과 요약"
echo "================================================"
echo "생성된 SARIF 파일들:"
ls -la trivy-results/*.sarif

echo ""
echo "📁 결과 파일 위치:"
echo "- IaC 스캔: trivy-results/trivy-iac-results.sarif"
echo "- Kubernetes Config: trivy-results/trivy-config-results.sarif"
echo "- Container Image: trivy-results/trivy-image-results.sarif"

echo ""
echo "🎉 Configuration Layer 스캔 완료!" 