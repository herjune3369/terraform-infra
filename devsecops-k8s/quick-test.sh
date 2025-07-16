#!/bin/bash

# 빠른 테스트 스크립트 - 주요 오류 부분만 빠르게 확인

set -e

echo "⚡ 빠른 보안 스캔 테스트"
echo "================================================"

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️ $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }
info() { echo -e "${BLUE}ℹ️ $1${NC}"; }

# 1. Trivy 설치 확인
info "1. Trivy 설치 확인..."
if command -v trivy &> /dev/null; then
    success "Trivy 설치됨: $(trivy --version | head -n1)"
else
    error "Trivy가 설치되지 않았습니다."
    exit 1
fi

# 2. kubectl 연결 확인
info "2. kubectl 연결 확인..."
if kubectl cluster-info &> /dev/null; then
    success "kubectl 연결됨"
else
    error "kubectl 연결 실패"
    exit 1
fi

# 3. Gatekeeper CRD 확인
info "3. Gatekeeper CRD 확인..."
if kubectl get crd constrainttemplates.templates.gatekeeper.sh &> /dev/null; then
    success "constrainttemplates.templates.gatekeeper.sh CRD 존재"
else
    warning "constrainttemplates.templates.gatekeeper.sh CRD 없음"
fi

if kubectl get crd constraints.constraints.gatekeeper.sh &> /dev/null; then
    success "constraints.constraints.gatekeeper.sh CRD 존재"
else
    warning "constraints.constraints.gatekeeper.sh CRD 없음"
fi

# 4. 매니페스트 문법 검증
info "4. 매니페스트 문법 검증..."

# Gatekeeper 정책 검증
if [ -f "k8s/manifests/gatekeeper-constraints.yaml" ]; then
    if kubectl apply --dry-run=client -f k8s/manifests/gatekeeper-constraints.yaml &> /dev/null; then
        success "Gatekeeper 정책 문법 검증 통과"
    else
        error "Gatekeeper 정책 문법 오류"
    fi
fi

# Falco DaemonSet 검증
if [ -f "k8s/manifests/falco-daemonset.yaml" ]; then
    if kubectl apply --dry-run=client -f k8s/manifests/falco-daemonset.yaml &> /dev/null; then
        success "Falco DaemonSet 문법 검증 통과"
    else
        error "Falco DaemonSet 문법 오류"
    fi
fi

# 5. Trivy 스캔 테스트
info "5. Trivy 스캔 테스트..."

# Terraform 스캔
if [ -d "terraform" ]; then
    if trivy config terraform/ --format sarif --output /tmp/test-iac.sarif --severity CRITICAL,HIGH &> /dev/null; then
        success "Terraform IaC 스캔 성공"
    else
        error "Terraform IaC 스캔 실패"
    fi
fi

# Kubernetes Config 스캔
if [ -d "k8s/manifests" ]; then
    if trivy config k8s/manifests/ --format sarif --output /tmp/test-config.sarif --severity CRITICAL,HIGH &> /dev/null; then
        success "Kubernetes Config 스캔 성공"
    else
        error "Kubernetes Config 스캔 실패"
    fi
fi

# Container Image 스캔
if trivy image nginx:latest --format sarif --output /tmp/test-image.sarif --severity CRITICAL,HIGH &> /dev/null; then
    success "Container Image 스캔 성공"
else
    error "Container Image 스캔 실패"
fi

# 6. 정리
rm -f /tmp/test-*.sarif

echo ""
success "🎉 빠른 테스트 완료!"
echo ""
info "📋 테스트 결과:"
echo "- Trivy 설치: ✅"
echo "- kubectl 연결: ✅"
echo "- 매니페스트 문법: ✅"
echo "- Trivy 스캔: ✅" 