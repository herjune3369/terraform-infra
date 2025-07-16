#!/bin/bash

# Gatekeeper CRD 설치 상태 확인 및 대기 스크립트
# GitHub Actions에서 발생한 CRD 문제를 로컬에서 해결

set -e

echo "🔒 Gatekeeper CRD 설치 상태 확인 및 테스트"
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

# kubectl 연결 확인
check_kubectl() {
    info "kubectl 연결 확인 중..."
    if ! kubectl cluster-info &> /dev/null; then
        error "kubectl이 클러스터에 연결되지 않았습니다."
        info "AWS EKS 클러스터에 연결하세요:"
        echo "aws eks update-kubeconfig --region ap-northeast-2 --name devsecops-eks-cluster"
        exit 1
    fi
    success "kubectl 연결 확인됨"
}

# Helm 설치 확인
check_helm() {
    info "Helm 설치 확인 중..."
    if ! command -v helm &> /dev/null; then
        error "Helm이 설치되지 않았습니다."
        info "Helm 설치 중..."
        curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    fi
    success "Helm 버전: $(helm version --short)"
}

# Gatekeeper 설치 확인
check_gatekeeper_installation() {
    info "Gatekeeper 설치 상태 확인 중..."
    
    # Gatekeeper 네임스페이스 확인
    if ! kubectl get namespace gatekeeper-system &> /dev/null; then
        warning "gatekeeper-system 네임스페이스가 없습니다."
        return 1
    fi
    
    # Gatekeeper Pod 상태 확인
    info "Gatekeeper Pod 상태:"
    kubectl get pods -n gatekeeper-system
    
    # Gatekeeper CRD 확인
    info "Gatekeeper CRD 확인:"
    kubectl get crd | grep gatekeeper || warning "Gatekeeper CRD가 없습니다."
    
    return 0
}

# Gatekeeper 설치
install_gatekeeper() {
    info "Gatekeeper 설치 중..."
    
    # Helm 저장소 추가
    helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
    helm repo update
    success "Gatekeeper Helm 저장소 추가 완료"
    
    # Gatekeeper 설치
    helm install gatekeeper gatekeeper/gatekeeper \
        --namespace gatekeeper-system \
        --create-namespace \
        --set auditInterval=60 \
        --set constraintViolationsLimit=20 \
        --set logLevel=INFO
    
    success "Gatekeeper 설치 완료"
}

# CRD 대기 함수
wait_for_crds() {
    info "Gatekeeper CRD가 준비될 때까지 대기 중..."
    
    local timeout=300  # 5분 타임아웃
    local interval=10  # 10초마다 확인
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        info "⏳ CRD 상태 확인 중... (${elapsed}s/${timeout}s)"
        
        # 필수 CRD들 확인
        local crds_ready=true
        
        # constrainttemplates.templates.gatekeeper.sh 확인
        if ! kubectl get crd constrainttemplates.templates.gatekeeper.sh &> /dev/null; then
            echo "  - constrainttemplates.templates.gatekeeper.sh: 대기 중..."
            crds_ready=false
        else
            echo "  - constrainttemplates.templates.gatekeeper.sh: ✅ 준비됨"
        fi
        
        # constraints.constraints.gatekeeper.sh 확인
        if ! kubectl get crd constraints.constraints.gatekeeper.sh &> /dev/null; then
            echo "  - constraints.constraints.gatekeeper.sh: 대기 중..."
            crds_ready=false
        else
            echo "  - constraints.constraints.gatekeeper.sh: ✅ 준비됨"
        fi
        
        # configs.config.gatekeeper.sh 확인
        if ! kubectl get crd configs.config.gatekeeper.sh &> /dev/null; then
            echo "  - configs.config.gatekeeper.sh: 대기 중..."
            crds_ready=false
        else
            echo "  - configs.config.gatekeeper.sh: ✅ 준비됨"
        fi
        
        if [ "$crds_ready" = true ]; then
            success "모든 Gatekeeper CRD가 준비되었습니다!"
            return 0
        fi
        
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    
    error "타임아웃: Gatekeeper CRD가 준비되지 않았습니다."
    return 1
}

# 정책 적용 테스트
test_policy_application() {
    info "정책 적용 테스트 중..."
    
    if [ -f "k8s/manifests/gatekeeper-constraints.yaml" ]; then
        # 문법 검증
        info "매니페스트 문법 검증 중..."
        kubectl apply --dry-run=client -f k8s/manifests/gatekeeper-constraints.yaml
        success "매니페스트 문법 검증 통과"
        
        # 실제 적용 (선택사항)
        read -p "정책을 실제로 적용하시겠습니까? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            kubectl apply -f k8s/manifests/gatekeeper-constraints.yaml
            success "정책 적용 완료"
            
            # 정책 상태 확인
            info "정책 상태 확인:"
            kubectl get constrainttemplates
            kubectl get constraints --all-namespaces
        fi
    else
        warning "gatekeeper-constraints.yaml 파일이 없습니다."
    fi
}

# 문제 해결 가이드
show_troubleshooting() {
    echo ""
    info "🔧 문제 해결 가이드"
    echo "================================================"
    echo "1. Gatekeeper Pod가 CrashLoopBackOff 상태인 경우:"
    echo "   kubectl describe pod -n gatekeeper-system"
    echo "   kubectl logs -n gatekeeper-system -l app=gatekeeper"
    echo ""
    echo "2. CRD가 설치되지 않은 경우:"
    echo "   kubectl get crd | grep gatekeeper"
    echo "   kubectl delete crd constrainttemplates.templates.gatekeeper.sh"
    echo "   kubectl delete crd constraints.constraints.gatekeeper.sh"
    echo "   kubectl delete crd configs.config.gatekeeper.sh"
    echo "   (그 후 Gatekeeper 재설치)"
    echo ""
    echo "3. 네임스페이스 문제인 경우:"
    echo "   kubectl delete namespace gatekeeper-system"
    echo "   (그 후 Gatekeeper 재설치)"
    echo ""
    echo "4. Helm 차트 문제인 경우:"
    echo "   helm uninstall gatekeeper -n gatekeeper-system"
    echo "   helm repo update"
    echo "   (그 후 Gatekeeper 재설치)"
}

# 메인 실행
main() {
    check_kubectl
    check_helm
    
    echo ""
    echo "🔍 현재 상태 확인"
    echo "================================================"
    
    if check_gatekeeper_installation; then
        success "Gatekeeper가 이미 설치되어 있습니다."
    else
        warning "Gatekeeper가 설치되지 않았습니다."
        read -p "Gatekeeper를 설치하시겠습니까? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_gatekeeper
        else
            error "Gatekeeper 설치가 필요합니다."
            exit 1
        fi
    fi
    
    echo ""
    echo "⏳ CRD 대기 및 확인"
    echo "================================================"
    
    if wait_for_crds; then
        success "CRD 대기 완료"
        
        echo ""
        echo "🧪 정책 테스트"
        echo "================================================"
        test_policy_application
        
        echo ""
        success "🎉 Gatekeeper CRD 테스트 완료!"
    else
        error "CRD 대기 실패"
        show_troubleshooting
        exit 1
    fi
}

# 스크립트 실행
main "$@" 