#!/bin/bash

# Policy Layer - Gatekeeper Installation Script
# OPA Gatekeeper를 EKS 클러스터에 설치

set -e

echo "🔒 Policy Layer - Gatekeeper 설치 시작"
echo "========================================"

# kubectl 연결 확인
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ kubectl이 클러스터에 연결되지 않았습니다."
    echo "AWS EKS 클러스터에 연결하세요:"
    echo "aws eks update-kubeconfig --region ap-northeast-2 --name devsecops-eks-cluster"
    exit 1
fi

echo "✅ kubectl 연결 확인됨"
kubectl cluster-info

# Helm 설치 확인
if ! command -v helm &> /dev/null; then
    echo "❌ Helm이 설치되지 않았습니다. 설치 중..."
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

echo "✅ Helm 버전: $(helm version --short)"

# Gatekeeper Helm 저장소 추가
echo ""
echo "📦 Gatekeeper Helm 저장소 추가 중..."
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update

# 기존 Gatekeeper 설치 확인
if helm list -n gatekeeper-system | grep -q gatekeeper; then
    echo "⚠️ Gatekeeper가 이미 설치되어 있습니다."
    echo "기존 설치 정보:"
    helm list -n gatekeeper-system
else
    echo ""
    echo "🔒 Gatekeeper 설치 중..."
    helm install gatekeeper gatekeeper/gatekeeper \
        --namespace gatekeeper-system \
        --create-namespace \
        --set auditInterval=60 \
        --set constraintViolationsLimit=20 \
        --set logLevel=INFO
    
    echo "✅ Gatekeeper 설치 완료"
fi

# 설치 확인
echo ""
echo "🔍 Gatekeeper 설치 상태 확인..."
kubectl get pods -n gatekeeper-system
kubectl get crd | grep gatekeeper

# 기본 정책 예시 생성
echo ""
echo "📋 기본 정책 예시 생성 중..."

# Pod Security Policy 예시
cat > gatekeeper-policies.yaml << 'EOF'
apiVersion: config.gatekeeper.sh/v1alpha1
kind: Config
metadata:
  name: config
  namespace: gatekeeper-system
spec:
  sync:
    syncOnly:
      - group: ""
        version: "v1"
        kind: "Pod"
      - group: "apps"
        version: "v1"
        kind: "Deployment"
      - group: "apps"
        version: "v1"
        kind: "DaemonSet"
---
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: podsecuritypolicy
spec:
  crd:
    spec:
      names:
        kind: PodSecurityPolicy
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package podsecuritypolicy
        
        violation[{"msg": msg}] {
          input.review.object.kind == "Pod"
          not input.review.object.spec.securityContext.runAsNonRoot
          msg := "Pods must not run as root"
        }
        
        violation[{"msg": msg}] {
          input.review.object.kind == "Pod"
          container := input.review.object.spec.containers[_]
          not container.securityContext.allowPrivilegeEscalation == false
          msg := sprintf("Container %v must not allow privilege escalation", [container.name])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: PodSecurityPolicy
metadata:
  name: pod-security-policy
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters: {}
EOF

echo "✅ 기본 정책 파일 생성: gatekeeper-policies.yaml"

echo ""
echo "🎉 Policy Layer - Gatekeeper 설치 완료!"
echo ""
echo "📋 다음 단계:"
echo "1. 정책 적용: kubectl apply -f gatekeeper-policies.yaml"
echo "2. 정책 확인: kubectl get constrainttemplates"
echo "3. 위반 사항 확인: kubectl get constraintviolations" 