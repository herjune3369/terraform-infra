#!/bin/bash

# 로컬 테스트 스크립트 - 각 보안 스캔 단계별 테스트
# GitHub Actions 워크플로우의 각 단계를 로컬에서 개별 실행

set -e

echo "🧪 로컬 보안 스캔 테스트 시작"
echo "================================================"

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 함수: 성공 메시지
success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# 함수: 경고 메시지
warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

# 함수: 오류 메시지
error() {
    echo -e "${RED}❌ $1${NC}"
}

# 함수: 정보 메시지
info() {
    echo -e "${BLUE}ℹ️ $1${NC}"
}

# Trivy 설치 확인
check_trivy() {
    info "Trivy 설치 확인 중..."
    if ! command -v trivy &> /dev/null; then
        error "Trivy가 설치되지 않았습니다."
        info "Trivy 설치 중..."
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.64.1
    fi
    success "Trivy 버전: $(trivy --version | head -n1)"
}

# 1. Configuration Layer 테스트
test_configuration_layer() {
    echo ""
    echo "🔍 1. Configuration Layer 테스트"
    echo "================================================"
    
    check_trivy
    
    # 결과 디렉토리 생성
    mkdir -p trivy-results
    
    # 1-1. IaC 스캔 테스트
    info "1-1. Terraform IaC 스캔 테스트..."
    if [ -d "terraform" ]; then
        cd terraform
        trivy config . --format sarif --output ../trivy-results/trivy-iac-results.sarif --severity CRITICAL,HIGH,MEDIUM,LOW
        success "IaC 스캔 완료: trivy-iac-results.sarif"
        cd ..
    else
        warning "terraform 디렉토리가 없습니다. 건너뜁니다."
    fi
    
    # 1-2. Kubernetes Config 스캔 테스트
    info "1-2. Kubernetes Config 스캔 테스트..."
    if [ -d "k8s/manifests" ]; then
        trivy config k8s/manifests/ --format sarif --output trivy-results/trivy-config-results.sarif --severity CRITICAL,HIGH,MEDIUM,LOW
        success "Kubernetes Config 스캔 완료: trivy-config-results.sarif"
    else
        warning "k8s/manifests 디렉토리가 없습니다. 건너뜁니다."
    fi
    
    # 1-3. Container Image 스캔 테스트
    info "1-3. Container Image 스캔 테스트..."
    trivy image nginx:latest --format sarif --output trivy-results/trivy-image-results.sarif --severity CRITICAL,HIGH,MEDIUM,LOW
    success "Container Image 스캔 완료: trivy-image-results.sarif"
    
    success "Configuration Layer 테스트 완료!"
}

# 2. Runtime Layer 테스트
test_runtime_layer() {
    echo ""
    echo "🔄 2. Runtime Layer 테스트"
    echo "================================================"
    
    # kubectl 연결 확인
    info "kubectl 연결 확인 중..."
    if ! kubectl cluster-info &> /dev/null; then
        error "kubectl이 클러스터에 연결되지 않았습니다."
        info "AWS EKS 클러스터에 연결하세요:"
        echo "aws eks update-kubeconfig --region ap-northeast-2 --name devsecops-eks-cluster"
        return 1
    fi
    success "kubectl 연결 확인됨"
    
    # 2-1. Falco DaemonSet 테스트
    info "2-1. Falco DaemonSet 테스트..."
    if [ -f "k8s/manifests/falco-daemonset.yaml" ]; then
        # Falco 매니페스트 문법 검증
        kubectl apply --dry-run=client -f k8s/manifests/falco-daemonset.yaml
        success "Falco DaemonSet 문법 검증 통과"
        
        # 실제 배포 (선택사항)
        read -p "Falco DaemonSet을 실제로 배포하시겠습니까? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            kubectl apply -f k8s/manifests/falco-daemonset.yaml
            success "Falco DaemonSet 배포 완료"
            
            # Pod 상태 확인
            info "Falco Pod 상태 확인 중..."
            kubectl get pods -n falco-system
        fi
    else
        warning "falco-daemonset.yaml 파일이 없습니다."
    fi
    
    # 2-2. Trivy Runtime 스캔 테스트
    info "2-2. Trivy Runtime 스캔 테스트..."
    # 현재 실행 중인 Pod들의 이미지 스캔
    kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort | uniq | while read image; do
        if [ ! -z "$image" ]; then
            info "이미지 스캔 중: $image"
            trivy image "$image" --format sarif --output "trivy-results/trivy-runtime-$(echo $image | tr '/' '_' | tr ':' '_').sarif" --severity CRITICAL,HIGH,MEDIUM,LOW
        fi
    done
    success "Runtime Layer 테스트 완료!"
}

# 3. Policy Layer 테스트
test_policy_layer() {
    echo ""
    echo "🔒 3. Policy Layer 테스트"
    echo "================================================"
    
    # kubectl 연결 확인
    info "kubectl 연결 확인 중..."
    if ! kubectl cluster-info &> /dev/null; then
        error "kubectl이 클러스터에 연결되지 않았습니다."
        return 1
    fi
    success "kubectl 연결 확인됨"
    
    # 3-1. Gatekeeper 설치 테스트
    info "3-1. Gatekeeper 설치 테스트..."
    
    # Helm 설치 확인
    if ! command -v helm &> /dev/null; then
        error "Helm이 설치되지 않았습니다."
        info "Helm 설치 중..."
        curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    fi
    success "Helm 버전: $(helm version --short)"
    
    # Gatekeeper Helm 저장소 추가
    helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
    helm repo update
    success "Gatekeeper Helm 저장소 추가 완료"
    
    # 3-2. Gatekeeper 매니페스트 문법 검증
    info "3-2. Gatekeeper 매니페스트 문법 검증..."
    if [ -f "k8s/manifests/gatekeeper-constraints.yaml" ]; then
        kubectl apply --dry-run=client -f k8s/manifests/gatekeeper-constraints.yaml
        success "Gatekeeper 매니페스트 문법 검증 통과"
    else
        warning "gatekeeper-constraints.yaml 파일이 없습니다."
    fi
    
    success "Policy Layer 테스트 완료!"
}

# 4. 전체 테스트
test_all() {
    echo ""
    echo "🚀 전체 보안 스캔 테스트"
    echo "================================================"
    
    test_configuration_layer
    test_runtime_layer
    test_policy_layer
    
    echo ""
    success "🎉 모든 테스트 완료!"
    echo ""
    info "📊 테스트 결과 요약:"
    echo "- Configuration Layer: IaC, Kubernetes Config, Container Image 스캔"
    echo "- Runtime Layer: Falco DaemonSet, Trivy Runtime 스캔"
    echo "- Policy Layer: Gatekeeper 설치 및 정책 검증"
    echo ""
    info "📁 결과 파일 위치: trivy-results/"
    ls -la trivy-results/*.sarif 2>/dev/null || echo "SARIF 파일이 생성되지 않았습니다."
}

# 메인 메뉴
show_menu() {
    echo ""
    echo "🧪 로컬 보안 스캔 테스트 메뉴"
    echo "================================================"
    echo "1. Configuration Layer 테스트 (IaC, K8s Config, Container Image)"
    echo "2. Runtime Layer 테스트 (Falco, Trivy Runtime)"
    echo "3. Policy Layer 테스트 (Gatekeeper)"
    echo "4. 전체 테스트"
    echo "5. 종료"
    echo ""
    read -p "선택하세요 (1-5): " choice
}

# 메인 실행
main() {
    case $1 in
        "config"|"1")
            test_configuration_layer
            ;;
        "runtime"|"2")
            test_runtime_layer
            ;;
        "policy"|"3")
            test_policy_layer
            ;;
        "all"|"4")
            test_all
            ;;
        *)
            while true; do
                show_menu
                case $choice in
                    1)
                        test_configuration_layer
                        ;;
                    2)
                        test_runtime_layer
                        ;;
                    3)
                        test_policy_layer
                        ;;
                    4)
                        test_all
                        ;;
                    5)
                        info "테스트를 종료합니다."
                        exit 0
                        ;;
                    *)
                        error "잘못된 선택입니다. 1-5 중에서 선택하세요."
                        ;;
                esac
            done
            ;;
    esac
}

# 스크립트 실행
main "$@" 