#!/usr/bin/env python3
"""
Trivy Security Report Generator
Trivy 스캔 결과를 파싱하고 AI 기반 종합 보안 보고서를 생성합니다.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

def parse_sarif_file(file_path: str) -> Dict:
    """SARIF 파일을 파싱하고 취약점 정보를 추출합니다."""
    if not os.path.exists(file_path):
        return {"error": "파일을 찾을 수 없습니다"}
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        results = []
        severity_counts = {"error": 0, "warning": 0, "note": 0, "none": 0}
        
        for run in data.get("runs", []):
            for result in run.get("results", []):
                severity = result.get("level", "none")
                severity_counts[severity] += 1
                
                results.append({
                    "message": result.get("message", {}).get("text", "설명 없음"),
                    "severity": severity,
                    "location": result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "알 수 없음"),
                    "rule_id": result.get("ruleId", "알 수 없음")
                })
        
        return {
            "total_vulnerabilities": len(results),
            "severity_distribution": severity_counts,
            "all_vulnerabilities": results  # 모든 취약점 포함
        }
    except Exception as e:
        return {"error": f"SARIF 파일 파싱 실패: {str(e)}"}

def parse_runtime_events(file_path: str) -> Dict:
    """런타임 이벤트 JSON 파일을 파싱합니다."""
    if not os.path.exists(file_path):
        return {"events": [], "total": 0}
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        events = []
        for event in data:
            events.append({
                "rule_id": event.get("ruleId", "알 수 없음"),
                "severity": event.get("level", "none"),
                "message": event.get("message", "설명 없음"),
                "location": event.get("location", "알 수 없음")
            })
        
        return {
            "events": events,
            "total": len(events)
        }
    except Exception as e:
        return {"events": [], "total": 0, "error": str(e)}

def parse_policy_violations(log_file: str, constraints_file: str) -> Dict:
    """정책 위반 로그와 제약 조건 파일을 파싱합니다."""
    violations = {"total": 0, "by_kind": {}, "details": []}
    
    # 로그 파일에서 총 위반 개수 읽기
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if "Policy Layer violations:" in line:
                        try:
                            violations["total"] = int(line.split(":")[1].strip())
                            break
                        except (ValueError, IndexError):
                            pass
        except:
            pass
    
    # 제약 조건 파일들 파싱
    if os.path.exists(constraints_file):
        try:
            with open(constraints_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for item in data.get("items", []):
                kind = item.get("kind", "Unknown")
                metadata = item.get("metadata", {})
                spec = item.get("spec", {})
                
                violation_detail = {
                    "kind": kind,
                    "name": metadata.get("name", "알 수 없음"),
                    "namespace": metadata.get("namespace", "알 수 없음"),
                    "enforcement_action": spec.get("enforcementAction", "deny"),
                    "match": spec.get("match", {}),
                    "parameters": spec.get("parameters", {})
                }
                
                violations["details"].append(violation_detail)
                
                if kind not in violations["by_kind"]:
                    violations["by_kind"][kind] = 0
                violations["by_kind"][kind] += 1
                
        except Exception as e:
            violations["error"] = str(e)
    
    return violations

def collect_unique_vulnerabilities(*sarif_results) -> list:
    """여러 SARIF 결과에서 중복 없는 취약점 리스트를 반환합니다."""
    seen = set()
    unique_vulns = []
    for result in sarif_results:
        if not result or "error" in result:
            continue
        for vuln in result.get("all_vulnerabilities", []):
            key = (vuln.get("rule_id"), vuln.get("message"), vuln.get("location"))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
    return unique_vulns

def translate_vulnerability_message(rule_id: str, message: str) -> str:
    """취약점 메시지를 한글로 번역합니다."""
    
    # KSV (Kubernetes Security Validator) 번역
    ksv_translations = {
        "KSV001": "컨테이너가 권한 상승을 허용하도록 설정되어 있습니다. 이는 컨테이너 내에서 실행되는 프로세스가 더 높은 권한으로 실행될 수 있음을 의미합니다. Kubernetes의 보안 모범 사례에 따르면 컨테이너는 최소 권한 원칙에 따라 실행되어야 하며, 권한 상승을 허용하지 않아야 합니다.",
        "KSV009": "DaemonSet이 호스트 네트워크를 사용하도록 설정되어 있습니다. 이는 컨테이너가 호스트의 네트워크 스택을 직접 사용하게 되어 네트워크 격리가 완전히 해제됩니다. 호스트 네트워크 사용은 컨테이너가 호스트의 모든 네트워크 인터페이스에 접근할 수 있게 하여 보안 위험을 크게 증가시킵니다.",
        "KSV010": "DaemonSet이 호스트 PID를 사용하도록 설정되어 있습니다. 이는 컨테이너가 호스트의 프로세스 네임스페이스를 공유하게 되어 호스트의 모든 프로세스 정보에 접근할 수 있음을 의미합니다. 호스트 PID 사용은 컨테이너 격리를 약화시키고 호스트 시스템의 프로세스 정보 노출을 야기합니다.",
        "KSV012": "컨테이너가 root 사용자로 실행되도록 설정되어 있습니다. 이는 컨테이너 내부의 프로세스가 root 권한으로 실행됨을 의미하며, 이는 가장 심각한 보안 위험 중 하나입니다. root 권한으로 실행되는 컨테이너는 호스트 시스템에 대한 완전한 접근 권한을 가질 수 있어 컨테이너 탈출 시 심각한 피해를 야기할 수 있습니다.",
        "KSV013": "컨테이너 이미지에 특정 태그가 지정되지 않았습니다. 이는 이미지 버전이 명확하지 않아 재현 가능한 배포가 어렵고, 악의적인 이미지로 교체될 위험이 있음을 의미합니다. 이미지 태그가 없는 경우 최신 버전을 가져오게 되어 예상치 못한 변경사항이나 보안 취약점이 포함될 수 있습니다.",
        "KSV014": "컨테이너의 루트 파일 시스템이 읽기 전용으로 설정되지 않았습니다. 이는 컨테이너 내부에서 파일을 생성하거나 수정할 수 있음을 의미하며, 이는 악성 코드 삽입이나 데이터 변조의 위험을 내포합니다. 읽기 전용 파일 시스템은 컨테이너의 무결성을 보장하고 공격자가 지속적인 접근을 확보하는 것을 방지합니다.",
        "KSV017": "컨테이너가 특권 모드로 실행되도록 설정되어 있습니다. 이는 컨테이너가 호스트 시스템의 모든 리소스와 장치에 직접 접근할 수 있음을 의미하며, 이는 가장 위험한 보안 설정 중 하나입니다. 특권 모드 컨테이너는 호스트의 모든 권한을 가지므로 컨테이너 탈출 시 호스트 시스템 전체가 위험에 노출됩니다.",
        "KSV041": "ClusterRole이 secrets 리소스에 대한 과도한 권한을 가지고 있습니다. 이는 해당 ClusterRole을 사용하는 서비스나 사용자가 클러스터의 모든 시크릿에 접근할 수 있음을 의미합니다. 시크릿에는 데이터베이스 비밀번호, API 키, 인증 토큰 등 민감한 정보가 포함되어 있어 과도한 접근 권한은 심각한 보안 위험을 야기합니다.",
    }
    
    # AVD (Aqua Vulnerability Database) 번역
    avd_translations = {
        "AVD-AWS-0028": "EC2 인스턴스가 IMDSv2 토큰을 요구하지 않도록 설정되어 있습니다. 이는 인스턴스 메타데이터 서비스(IMDS)가 버전 1을 사용하여 실행됨을 의미하며, 이는 보안상 취약한 설정입니다. IMDSv1은 토큰 기반 인증을 요구하지 않아 인스턴스 내부에서 메타데이터에 쉽게 접근할 수 있어 IAM 역할 자격 증명 탈취의 위험이 있습니다.",
        "AVD-AWS-0052": "애플리케이션 로드 밸런서가 유효하지 않은 헤더를 드롭하도록 설정되지 않았습니다. 이는 악의적인 사용자가 유효하지 않은 HTTP 헤더를 포함한 요청을 보낼 수 있음을 의미하며, 이는 HTTP 요청 조작 공격이나 헤더 기반 보안 우회 공격의 가능성을 내포합니다. 유효하지 않은 헤더를 자동으로 드롭하는 설정은 이러한 공격을 방지하는 중요한 보안 조치입니다.",
        "AVD-AWS-0053": "로드 밸런서가 공개적으로 노출되어 있습니다. 이는 인터넷에서 직접 로드 밸런서에 접근할 수 있음을 의미하며, 이는 의도하지 않은 공개 노출일 수 있습니다. 공개적으로 노출된 로드 밸런서는 DDoS 공격, 무차별 대입 공격, 또는 스캔 공격의 대상이 될 수 있으며, 적절한 네트워크 보안 그룹 설정이나 VPC 격리가 필요합니다.",
        "AVD-AWS-0054": "애플리케이션 로드 밸런서 리스너가 HTTPS를 사용하지 않습니다. 이는 클라이언트와 로드 밸런서 간의 통신이 암호화되지 않음을 의미하며, 이는 중간자 공격(Man-in-the-Middle)의 위험을 내포합니다. HTTP 트래픽은 네트워크 상에서 평문으로 전송되어 로그인 정보, 개인정보, 민감한 비즈니스 데이터 등이 노출될 수 있습니다.",
    }
    
    # 번역된 메시지 반환
    if rule_id in ksv_translations:
        return ksv_translations[rule_id]
    elif rule_id in avd_translations:
        return avd_translations[rule_id]
    else:
        # 번역이 없는 경우 원본 메시지에서 핵심 내용 추출
        if "hostNetwork" in message:
            return "호스트 네트워크 사용이 허용되어 있습니다."
        elif "hostPID" in message:
            return "호스트 PID 사용이 허용되어 있습니다."
        elif "privileged" in message:
            return "특권 모드 사용이 허용되어 있습니다."
        elif "readOnlyRootFilesystem" in message:
            return "루트 파일 시스템이 읽기 전용으로 설정되지 않았습니다."
        elif "runAsNonRoot" in message:
            return "root 사용자로 실행되도록 설정되어 있습니다."
        elif "allowPrivilegeEscalation" in message:
            return "권한 상승이 허용되어 있습니다."
        elif "image tag" in message:
            return "이미지 태그가 지정되지 않았습니다."
        elif "secrets" in message:
            return "시크릿 리소스에 대한 과도한 권한이 있습니다."
        elif "IMDS" in message:
            return "IMDSv2 토큰 요구가 설정되지 않았습니다."
        elif "HTTPS" in message:
            return "HTTPS가 사용되지 않습니다."
        elif "encryption" in message:
            return "암호화가 설정되지 않았습니다."
        else:
            return message  # 번역할 수 없는 경우 원본 반환

def get_hacking_scenario(rule_id: str, message: str) -> str:
    """취약점에 대한 해킹 시나리오를 반환합니다."""
    
    # KSV (Kubernetes Security Validator) 해킹 시나리오
    ksv_scenarios = {
        "KSV001": "공격자가 컨테이너 내에서 권한을 상승시켜 호스트 시스템에 접근할 수 있습니다. 이는 컨테이너 탈출 공격의 전형적인 경로로, 공격자가 컨테이너 내부에서 더 높은 권한을 얻은 후 호스트 시스템의 리소스에 접근할 수 있게 됩니다. 권한 상승이 허용된 컨테이너는 공격자가 시스템 관리자 권한을 획득하여 데이터 탈취, 악성 코드 설치, 또는 다른 컨테이너에 대한 공격을 수행할 수 있는 발판이 됩니다.",
        "KSV009": "공격자가 호스트 네트워크를 통해 호스트의 모든 네트워크 인터페이스에 직접 접근할 수 있습니다. 이는 네트워크 스니핑 및 호스트 네트워크 공격을 가능하게 하며, 공격자가 호스트 시스템의 네트워크 트래픽을 모니터링하여 민감한 정보를 탈취할 수 있습니다. 호스트 네트워크 사용은 컨테이너가 호스트의 네트워크 스택을 직접 사용하게 되어 네트워크 격리가 완전히 해제되므로, 공격자가 다른 서비스나 시스템에 대한 네트워크 공격을 수행할 수 있는 기회를 제공합니다.",
        "KSV010": "공격자가 호스트의 모든 프로세스 정보에 접근할 수 있어 민감한 정보를 수집하거나 호스트 프로세스를 조작할 수 있습니다. 이는 호스트 시스템의 프로세스 목록, 실행 중인 서비스, 사용자 정보 등 민감한 시스템 정보를 노출시킵니다. 공격자는 이러한 정보를 활용하여 시스템 구조를 파악하고 추가적인 공격 경로를 찾거나, 특정 프로세스를 조작하여 악성 코드를 실행하거나 데이터를 탈취할 수 있습니다.",
        "KSV012": "공격자가 root 권한으로 실행되는 컨테이너를 통해 호스트 시스템의 모든 리소스에 접근할 수 있습니다. 이는 가장 심각한 컨테이너 탈출 위험을 야기하며, root 권한으로 실행되는 컨테이너는 호스트 시스템에 대한 완전한 접근 권한을 가집니다. 공격자가 컨테이너를 탈출할 경우 호스트의 모든 파일, 프로세스, 네트워크 설정에 접근할 수 있어 데이터 탈취, 시스템 조작, 또는 다른 시스템에 대한 공격을 수행할 수 있습니다.",
        "KSV013": "공격자가 이미지 태그가 없는 컨테이너를 악의적인 이미지로 교체할 수 있습니다. 이는 supply chain 공격의 전형적인 기법으로, 공격자가 이미지 레지스트리에 악성 코드가 포함된 이미지를 업로드하고 이를 최신 버전으로 위장할 수 있습니다. 이미지 태그가 없는 경우 시스템이 자동으로 최신 버전을 가져오게 되어 예상치 못한 악성 코드가 실행될 수 있으며, 이는 데이터 탈취, 백도어 설치, 또는 다른 보안 위협을 야기할 수 있습니다.",
        "KSV014": "공격자가 컨테이너 내에서 파일을 생성하거나 수정할 수 있어 악성 코드 삽입이나 데이터 변조가 가능합니다. 이는 공격자가 컨테이너 내부에 악성 스크립트나 바이너리를 저장하여 지속적인 접근을 확보할 수 있음을 의미합니다. 읽기 전용이 아닌 파일 시스템은 공격자가 시스템 설정을 변경하거나, 로그 파일을 조작하여 공격 흔적을 지우거나, 또는 다른 악성 파일을 생성하여 추가적인 공격을 수행할 수 있는 기회를 제공합니다.",
        "KSV017": "공격자가 특권 모드 컨테이너를 통해 호스트의 모든 리소스와 장치에 직접 접근할 수 있습니다. 이는 가장 위험한 컨테이너 탈출 시나리오로, 특권 모드 컨테이너는 호스트 시스템의 모든 권한을 가지므로 공격자가 호스트의 모든 파일, 프로세스, 네트워크, 장치에 완전한 접근 권한을 가집니다. 공격자가 컨테이너를 탈출할 경우 호스트 시스템 전체를 제어할 수 있어 데이터 탈취, 시스템 파괴, 또는 다른 시스템에 대한 공격을 수행할 수 있으며, 이는 전체 인프라의 보안을 심각하게 위협합니다.",
        "KSV041": "공격자가 ClusterRole의 과도한 권한을 악용하여 클러스터의 모든 시크릿에 접근할 수 있습니다. 이는 인증 정보 탈취로 이어질 수 있으며, 시크릿에는 데이터베이스 비밀번호, API 키, 인증 토큰, SSL 인증서 등 민감한 정보가 포함되어 있습니다. 공격자가 이러한 정보를 탈취할 경우 데이터베이스에 무단 접근하거나, 외부 서비스에 대한 인증을 우회하거나, 또는 다른 시스템에 대한 공격을 수행할 수 있습니다. 과도한 권한은 최소 권한 원칙을 위반하여 불필요한 보안 위험을 야기합니다.",
    }
    
    # AVD (Aqua Vulnerability Database) 해킹 시나리오
    avd_scenarios = {
        "AVD-AWS-0028": "공격자가 IMDSv1을 통해 EC2 인스턴스의 메타데이터에 접근하여 IAM 역할 자격 증명을 탈취할 수 있습니다. 이는 AWS 계정 전체에 대한 접근 권한을 얻는 데 사용될 수 있으며, 공격자가 인스턴스 내부에서 HTTP 요청을 통해 메타데이터 서비스에 접근하여 IAM 역할의 임시 자격 증명을 획득할 수 있습니다. 이러한 자격 증명을 악용하여 공격자는 S3 버킷, RDS 데이터베이스, Lambda 함수 등 AWS 리소스에 무단 접근하거나, 다른 EC2 인스턴스에 접근하여 추가적인 공격을 수행할 수 있습니다.",
        "AVD-AWS-0052": "공격자가 유효하지 않은 헤더를 통해 로드 밸런서를 우회하거나 HTTP 요청 조작 공격을 수행할 수 있습니다. 이는 공격자가 악의적인 HTTP 헤더를 포함한 요청을 보내 로드 밸런서의 보안 검증을 우회할 수 있음을 의미하며, 이러한 공격은 웹 애플리케이션의 인증 메커니즘을 우회하거나, 캐시 중독 공격을 수행하거나, 또는 다른 보안 제어를 무력화하는 데 사용될 수 있습니다. 유효하지 않은 헤더를 자동으로 드롭하지 않는 설정은 이러한 공격을 방지하지 못하여 애플리케이션의 보안을 심각하게 위협합니다.",
        "AVD-AWS-0053": "공격자가 인터넷에서 직접 로드 밸런서에 접근할 수 있어 DDoS 공격이나 무차별 대입 공격의 대상이 될 수 있습니다. 이는 로드 밸런서가 공개적으로 노출되어 있어 의도하지 않은 접근이 가능함을 의미하며, 공격자는 대량의 트래픽을 보내 서비스를 마비시키거나, 무차별 대입 공격을 통해 인증 정보를 탈취하거나, 또는 스캔 공격을 통해 시스템 정보를 수집할 수 있습니다. 공개적으로 노출된 로드 밸런서는 적절한 네트워크 보안 그룹 설정이나 VPC 격리가 없을 경우 심각한 보안 위험을 야기합니다.",
        "AVD-AWS-0054": "공격자가 HTTP 트래픽을 가로채어 민감한 데이터(로그인 정보, 개인정보 등)를 탈취할 수 있습니다. 이는 중간자 공격(Man-in-the-Middle)의 전형적인 시나리오로, HTTP 트래픽이 암호화되지 않아 네트워크 상에서 평문으로 전송되므로 공격자가 네트워크 패킷을 가로채어 사용자의 로그인 정보, 개인정보, 신용카드 정보, 또는 기타 민감한 비즈니스 데이터를 탈취할 수 있습니다. HTTPS를 사용하지 않는 설정은 데이터 기밀성을 보장하지 못하여 사용자 프라이버시와 비즈니스 보안을 심각하게 위협합니다.",
    }
    
    # 해킹 시나리오 반환
    if rule_id in ksv_scenarios:
        return ksv_scenarios[rule_id]
    elif rule_id in avd_scenarios:
        return avd_scenarios[rule_id]
    else:
        # 일반적인 해킹 시나리오
        if "hostNetwork" in message:
            return "공격자가 호스트 네트워크를 통해 호스트 시스템의 네트워크 트래픽을 모니터링하거나 조작할 수 있습니다."
        elif "hostPID" in message:
            return "공격자가 호스트의 프로세스 정보를 수집하여 시스템 구조를 파악하고 추가 공격 경로를 찾을 수 있습니다."
        elif "privileged" in message:
            return "공격자가 특권 모드 컨테이너를 통해 호스트 시스템에 완전한 접근 권한을 얻을 수 있습니다."
        elif "readOnlyRootFilesystem" in message:
            return "공격자가 컨테이너 내에서 악성 파일을 생성하거나 기존 파일을 수정하여 지속적인 접근을 확보할 수 있습니다."
        elif "runAsNonRoot" in message:
            return "공격자가 root 권한을 통해 호스트 시스템의 모든 리소스에 접근하여 데이터 탈취나 시스템 조작을 수행할 수 있습니다."
        elif "allowPrivilegeEscalation" in message:
            return "공격자가 컨테이너 내에서 권한을 상승시켜 더 높은 권한으로 시스템에 접근할 수 있습니다."
        elif "image tag" in message:
            return "공격자가 이미지 태그가 없는 컨테이너를 악의적인 이미지로 교체하여 악성 코드를 실행할 수 있습니다."
        elif "secrets" in message:
            return "공격자가 과도한 권한을 악용하여 민감한 인증 정보나 시크릿에 접근할 수 있습니다."
        elif "IMDS" in message:
            return "공격자가 IMDSv1을 통해 EC2 인스턴스의 메타데이터에서 IAM 역할 자격 증명을 탈취할 수 있습니다."
        elif "HTTPS" in message:
            return "공격자가 HTTP 트래픽을 가로채어 사용자의 민감한 정보(비밀번호, 개인정보 등)를 탈취할 수 있습니다."
        elif "encryption" in message:
            return "공격자가 암호화되지 않은 데이터에 직접 접근하여 민감한 정보를 탈취할 수 있습니다."
        else:
            return "이 취약점은 공격자가 시스템에 대한 무단 접근을 얻거나 민감한 정보를 탈취할 수 있는 위험을 내포합니다."

def generate_ai_report(trivy_fs_results: Dict, trivy_iac_results: Dict, trivy_config_results: Dict = None, trivy_image_results: Dict = None, runtime_events: Dict = None, policy_violations: Dict = None) -> str:
    """AI 기반 보안 보고서를 생성합니다."""
    
    # 중복 없는 취약점 집계
    all_unique_vulns = collect_unique_vulnerabilities(trivy_fs_results, trivy_iac_results, trivy_image_results)
    total_vulns = len(all_unique_vulns)
    total_high = sum(1 for v in all_unique_vulns if v.get("severity") == "error")
    total_medium = sum(1 for v in all_unique_vulns if v.get("severity") == "warning")
    total_low = sum(1 for v in all_unique_vulns if v.get("severity") == "note")

    # AI 분석 및 권장사항 생성
    ai_analysis = generate_ai_analysis(total_high, total_medium, total_low, trivy_fs_results, trivy_iac_results, runtime_events, policy_violations)
    
    # 전체 보안 상태 결정
    if total_high > 0:
        overall_status = "🔴 위험"
        status_emoji = "❌"
    elif total_medium > 0:
        overall_status = "🟡 주의"
        status_emoji = "⚠️"
    else:
        overall_status = "🟢 양호"
        status_emoji = "✅"
    
    report = f"""# 🛡️ 3계층 보안 종합 분석 보고서

<div align="center">

## 📊 보안 스캔 결과 요약

| 계층 | 상태 | 발견 문제 | 높음 | 중간 | 낮음 |
|------|------|-----------|------|------|------|
| **Configuration** | {'🔴 위험' if total_high > 0 else '🟡 주의' if total_medium > 0 else '🟢 양호'} | {total_vulns}개 | {total_high}개 | {total_medium}개 | {total_low}개 |
| **Runtime** | {'🔴 위험' if runtime_events.get('total', 0) > 0 else '🟢 양호'} | {runtime_events.get('total', 0)}개 | - | - | - |
| **Policy** | {'🔴 위험' if policy_violations.get('total', 0) > 0 else '🟢 양호'} | {policy_violations.get('total', 0)}개 | - | - | - |

### 🎯 **전체 보안 상태: {overall_status}** {status_emoji}

</div>

---

## 📅 스캔 정보
- **스캔 날짜**: {datetime.now().strftime('%Y년 %m월 %d일 %H:%M:%S')}
- **브랜치**: `{os.environ.get('GITHUB_REF', '알 수 없음')}`
- **커밋**: `{os.environ.get('GITHUB_SHA', '알 수 없음')[:8]}`
- **저장소**: `{os.environ.get('GITHUB_REPOSITORY', '알 수 없음')}`

---

## 🏗️ 3계층 보안 모델 상세 설명

### 1️⃣ **Configuration Layer (구성 계층)** 🔧

**상세 설명**:
Configuration Layer는 **코드와 설정 파일에서 보안 취약점을 미리 찾아내는 계층**입니다. 이 계층은 애플리케이션이나 인프라가 실제로 배포되기 전에 정적 분석을 통해 잠재적인 보안 문제를 사전에 발견하고 해결하는 것이 목적입니다. 

주요 검사 대상으로는 Docker 이미지의 보안 취약점, Kubernetes 매니페스트의 보안 설정, Terraform 등 IaC(Infrastructure as Code) 파일의 보안 구성, 그리고 애플리케이션 소스 코드의 보안 문제가 포함됩니다. 

이 계층에서는 Trivy와 같은 도구를 사용하여 취약점 스캔을 수행하며, CI/CD 파이프라인에 통합되어 코드가 저장소에 푸시될 때마다 자동으로 실행됩니다. 이를 통해 보안 문제를 조기에 발견하고 수정할 수 있어, 런타임에서 발생할 수 있는 보안 사고를 예방할 수 있습니다.

**대표 진단항목 예시**:

1. **KSV014 (Kubernetes Security Validator)**: 
   - **문제**: 컨테이너의 루트 파일 시스템이 읽기 전용으로 설정되지 않음
   - **위험**: 공격자가 컨테이너 내에서 파일을 생성하거나 수정하여 악성 코드 삽입 가능
   - **해결**: `securityContext.readOnlyRootFilesystem: true` 설정 추가

2. **AVD-AWS-0028 (AWS 보안 취약점)**:
   - **문제**: EC2 인스턴스가 IMDSv2 토큰을 요구하지 않도록 설정됨
   - **위험**: 공격자가 IMDSv1을 통해 IAM 역할 자격 증명 탈취 가능
   - **해결**: `metadata_options.http_tokens = "required"` 설정 추가

3. **CVE-2024-1234 (컨테이너 이미지 취약점)**:
   - **문제**: nginx:latest 이미지에 알려진 보안 취약점 존재
   - **위험**: 공격자가 취약점을 악용하여 컨테이너 탈출 또는 권한 상승 가능
   - **해결**: 최신 보안 패치가 적용된 이미지 버전으로 업데이트

---

### 2️⃣ **Runtime Layer (런타임 계층)** ⚡

**상세 설명**:
Runtime Layer는 **실제로 시스템이 실행되는 동안 발생하는 보안 위협을 실시간으로 감지하고 대응하는 계층**입니다. 이 계층은 애플리케이션이나 인프라가 운영 중일 때 발생하는 동적인 보안 이벤트를 모니터링하며, 비정상적인 행동 패턴이나 공격 시도를 즉시 감지합니다.

주요 검사 대상으로는 실행 중인 컨테이너의 보안 이벤트, 애플리케이션의 비정상적인 동작 패턴, 네트워크 트래픽의 이상 징후, 그리고 시스템 리소스(CPU, 메모리, 디스크)의 비정상적인 사용량이 포함됩니다. 

이 계층에서는 Trivy Container Security, Falco 등의 도구를 사용하여 실시간 모니터링을 수행하며, 감지된 위협에 대해 즉시 알림을 발생시키거나 자동으로 대응 조치를 취할 수 있습니다. 이를 통해 공격이 진행되는 동안 실시간으로 대응할 수 있어, 보안 사고의 피해를 최소화할 수 있습니다.

**대표 진단항목 예시**:

1. **컨테이너 프로세스 실행 감지**:
   - **문제**: 컨테이너 내에서 의심스러운 프로세스 실행 (bash, sh 등)
   - **위험**: 공격자가 컨테이너 내에서 악성 스크립트 실행 가능
   - **해결**: 프로세스 실행 로그 분석 및 의심스러운 프로세스 차단

2. **네트워크 연결 이상 감지**:
   - **문제**: 컨테이너에서 외부로의 의심스러운 네트워크 연결 시도
   - **위험**: 공격자가 외부 C&C 서버와 통신하여 데이터 탈취 가능
   - **해결**: 네트워크 정책을 통한 비정상 연결 차단 및 로그 분석

3. **파일 시스템 접근 이상**:
   - **문제**: 컨테이너 내에서 민감한 파일에 대한 비정상적인 접근 시도
   - **위험**: 공격자가 민감한 데이터를 읽거나 수정 가능
   - **해결**: 파일 접근 로그 모니터링 및 접근 권한 제한

---

### 3️⃣ **Policy Layer (정책 계층)** 📋

**상세 설명**:
Policy Layer는 **조직의 보안 정책을 자동으로 적용하고 위반 사항을 차단하는 계층**입니다. 이 계층은 Kubernetes 리소스가 생성되거나 수정될 때 조직에서 정의한 보안 정책을 자동으로 검사하며, 정책을 위반하는 리소스의 생성을 차단하거나 경고를 발생시킵니다.

주요 검사 대상으로는 Kubernetes 리소스 생성/수정 시 정책 준수 여부, 사용자 권한 및 역할 기반 접근 제어(RBAC), 조직 보안 정책 위반 사항, 그리고 정책 위반 시 자동 차단 및 알림이 포함됩니다. 

이 계층에서는 Gatekeeper와 같은 정책 엔진을 사용하여 정책을 정의하고 적용하며, OPA(Open Policy Agent) 언어를 사용하여 복잡한 정책 규칙을 작성할 수 있습니다. 이를 통해 일관된 보안 정책을 조직 전체에 적용할 수 있어, 보안 표준을 유지하고 규정 준수를 보장할 수 있습니다.

**대표 진단항목 예시**:

1. **컨테이너 보안 정책 위반**:
   - **문제**: 특권 모드로 실행되는 컨테이너 생성 시도
   - **위험**: 공격자가 특권 모드 컨테이너를 통해 호스트 시스템 접근 가능
   - **해결**: 정책을 통해 특권 모드 컨테이너 생성 자동 차단

2. **리소스 제한 정책 위반**:
   - **문제**: 리소스 제한이 설정되지 않은 Pod 생성 시도
   - **위험**: 리소스 제한이 없는 Pod가 클러스터 리소스를 과도하게 사용 가능
   - **해결**: 정책을 통해 리소스 제한이 없는 Pod 생성 자동 차단

3. **네트워크 정책 위반**:
   - **문제**: 네트워크 정책이 정의되지 않은 네임스페이스에서 Pod 생성 시도
   - **위험**: 네트워크 격리가 되지 않은 Pod 간 무제한 통신 가능
   - **해결**: 정책을 통해 네트워크 정책이 없는 Pod 생성 시 경고 발생

---

## 🛡️ **3계층 보안 모델의 통합 효과**

이 세 계층이 함께 작동할 때 **방어의 깊이(Defense in Depth)** 전략을 구현할 수 있습니다:

- **Configuration Layer**: 배포 전 보안 문제 사전 차단
- **Runtime Layer**: 운영 중 실시간 위협 감지 및 대응  
- **Policy Layer**: 조직 정책 기반 일관된 보안 강제

이를 통해 **사전 예방 → 실시간 감지 → 정책 기반 차단**의 완전한 보안 생태계를 구축할 수 있습니다!

---

## 🔍 상세 분석 결과

### 📊 전체 통계
- **총 보안 문제 수**: **{total_vulns}개**
- **높은 심각도**: **{total_high}개** (즉시 조치 필요)
- **중간 심각도**: **{total_medium}개** (계획적 조치 필요)
- **낮은 심각도**: **{total_low}개** (모니터링 필요)

{ai_analysis}

---

## 🚨 우선순위별 조치 계획

### 🔴 **즉시 조치 필요 (우선순위 1)**
{'**' + str(total_high) + '개의 높은 심각도 문제**가 발견되어 **즉각적인 조치**가 필요합니다.' if total_high > 0 else '높은 심각도 문제가 발견되지 않았습니다.'}

### 🟡 **계획적 조치 필요 (우선순위 2)**
{'**' + str(total_medium) + '개의 중간 심각도 문제**에 대한 해결 계획을 수립해야 합니다.' if total_medium > 0 else '중간 심각도 문제가 발견되지 않았습니다.'}

### 🟢 **모니터링 필요 (우선순위 3)**
{'**' + str(total_low) + '개의 낮은 심각도 문제**를 지속적으로 모니터링해야 합니다.' if total_low > 0 else '낮은 심각도 문제가 발견되지 않았습니다.'}

---

## 📋 다음 단계

1. **GitHub Security 탭**에서 모든 결과를 면밀히 검토
2. **높은 심각도 문제**부터 순차적으로 해결
3. **의존성 패키지**를 최신 보안 패치 버전으로 업데이트
4. **Terraform 설정**을 보안 권장사항에 따라 수정
5. **정기적인 보안 스캔** 일정 수립

---

*이 보고서는 Trivy 3계층 보안 스캔 파이프라인에 의해 자동으로 생성되었습니다.*
"""

    return report

def generate_ai_analysis(high_count: int, medium_count: int, low_count: int, 
                        trivy_fs: Dict, trivy_iac: Dict, runtime_events: Dict = None, policy_violations: Dict = None) -> str:
    """AI 기반 보안 분석 및 권장사항을 생성합니다."""
    
    analysis = ""
    
    # 전체 위험도 평가
    if high_count == 0 and medium_count == 0:
        analysis += "## 🟢 **보안 상태: 양호** ✅\n\n"
        analysis += "현재 프로젝트의 보안 상태는 양호합니다. 발견된 문제가 없거나 모두 낮은 심각도입니다.\n\n"
    elif high_count > 0:
        analysis += f"## 🔴 **보안 상태: 위험** ❌\n\n"
        analysis += f"**{high_count}개의 높은 심각도 문제**가 발견되어 **즉각적인 조치**가 필요합니다.\n\n"
    elif medium_count > 0:
        analysis += f"## 🟡 **보안 상태: 주의** ⚠️\n\n"
        analysis += f"**{medium_count}개의 중간 심각도 문제**가 발견되어 우선순위를 정해 해결해야 합니다.\n\n"
    
    analysis += "---\n\n"
    
    # Configuration Layer 상세 분석
    if "error" not in trivy_fs and trivy_fs.get("total_vulnerabilities", 0) > 0:
        analysis += "## 🔧 **Configuration Layer (구성 계층) 분석**\n\n"
        analysis += "### 📋 구성 계층이란?\n\n"
        analysis += "구성 계층은 **코드와 설정 파일**에서 보안 취약점을 미리 찾아내는 계층입니다.\n\n"
        analysis += "**주요 검사 대상**:\n"
        analysis += "- 🐳 **Docker 이미지**: 컨테이너 이미지의 보안 취약점\n"
        analysis += "- ☸️ **Kubernetes 매니페스트**: YAML 파일의 보안 설정\n"
        analysis += "- 📦 **애플리케이션 코드**: 소스 코드의 보안 문제\n"
        analysis += "- 🔧 **설정 파일**: 환경 설정의 보안 취약점\n\n"
        
        # 심각도별 분류
        high_vulns = [v for v in trivy_fs.get("all_vulnerabilities", []) if v['severity'] == 'error']
        medium_vulns = [v for v in trivy_fs.get("all_vulnerabilities", []) if v['severity'] == 'warning']
        low_vulns = [v for v in trivy_fs.get("all_vulnerabilities", []) if v['severity'] == 'note']
        
        # 통계 테이블 (조치 필요성 컬럼 추가)
        analysis += "### 📊 구성 계층 통계\n\n"
        analysis += "| 심각도 | 개수 | 상태 | 조치 필요성 |\n"
        analysis += "|--------|------|------|-------------|\n"
        analysis += f"| 🔴 높음 | {len(high_vulns)}개 | {'❌ 위험' if len(high_vulns) > 0 else '✅ 양호'} | 즉시 조치 |\n"
        analysis += f"| 🟡 중간 | {len(medium_vulns)}개 | {'⚠️ 주의' if len(medium_vulns) > 0 else '✅ 양호'} | 계획적 조치 |\n"
        analysis += f"| 🟢 낮음 | {len(low_vulns)}개 | {'ℹ️ 정보' if len(low_vulns) > 0 else '✅ 양호'} | 모니터링 |\n\n"
        
        if high_vulns:
            analysis += "### 🔴 **높은 심각도 문제 (즉시 조치 필요)**\n\n"
            for i, vuln in enumerate(high_vulns[:5], 1):
                analysis += f"#### {i}. **{vuln['rule_id']}**\n\n"
                analysis += f"**📍 위치**: `{vuln['location']}`\n\n"
                analysis += f"**📝 문제 설명**:\n{translate_vulnerability_message(vuln['rule_id'], vuln['message'])}\n\n"
                analysis += f"**🚨 해킹 시나리오**:\n{get_hacking_scenario(vuln['rule_id'], vuln['message'])}\n\n"
                analysis += "**🔗 관련 링크**: [자세한 정보](https://avd.aquasec.com/misconfig/" + vuln['rule_id'].lower() + ")\n\n"
                analysis += "**🛠️ 조치 방법**:\n"
                
                # 구체적인 조치 방법 추가
                if "hostNetwork" in vuln['message']:
                    analysis += "- 컨테이너 설정에서 `hostNetwork: true`를 제거\n"
                    analysis += "- 필요한 경우 서비스나 인그레스를 사용하여 네트워크 접근 제공\n"
                elif "hostPID" in vuln['message']:
                    analysis += "- 컨테이너 설정에서 `hostPID: true`를 제거\n"
                    analysis += "- 컨테이너 격리 수준을 유지하여 보안 강화\n"
                elif "privileged" in vuln['message']:
                    analysis += "- 컨테이너 설정에서 `privileged: true`를 제거\n"
                    analysis += "- 필요한 경우 `securityContext.capabilities`를 사용하여 최소 권한 원칙 적용\n"
                elif "readOnlyRootFilesystem" in vuln['message']:
                    analysis += "- 컨테이너 설정에 `securityContext.readOnlyRootFilesystem: true` 추가\n"
                    analysis += "- 파일 시스템을 읽기 전용으로 설정하여 무결성 보장\n"
                elif "secrets" in vuln['message']:
                    analysis += "- ClusterRole에서 secrets 리소스 접근 권한을 제거\n"
                    analysis += "- 더 구체적인 권한으로 제한하여 최소 권한 원칙 적용\n"
                else:
                    analysis += "- 해당 설정을 보안 모범 사례에 따라 수정\n"
                    analysis += "- Kubernetes 보안 컨텍스트 가이드라인 준수\n"
                analysis += "\n---\n\n"
            
            if len(high_vulns) > 5:
                analysis += f"**... 및 {len(high_vulns) - 5}개 더**\n\n"
        
        if medium_vulns:
            analysis += "### 🟡 **중간 심각도 문제 (계획적 조치 필요)**\n\n"
            for i, vuln in enumerate(medium_vulns[:3], 1):
                analysis += f"#### {i}. **{vuln['rule_id']}**\n\n"
                analysis += f"**📍 위치**: `{vuln['location']}`\n\n"
                analysis += f"**📝 문제 설명**:\n{translate_vulnerability_message(vuln['rule_id'], vuln['message'])}\n\n"
                analysis += f"**🚨 해킹 시나리오**:\n{get_hacking_scenario(vuln['rule_id'], vuln['message'])}\n\n"
                analysis += "**🛠️ 조치 방법**:\n"
                
                if "allowPrivilegeEscalation" in vuln['message']:
                    analysis += "- 컨테이너 설정에 `securityContext.allowPrivilegeEscalation: false` 추가\n"
                    analysis += "- 권한 상승을 방지하여 보안 강화\n"
                elif "runAsNonRoot" in vuln['message']:
                    analysis += "- 컨테이너 설정에 `securityContext.runAsNonRoot: true` 추가\n"
                    analysis += "- root 사용자로 실행하지 않도록 설정\n"
                elif "image tag" in vuln['message']:
                    analysis += "- 컨테이너 이미지에 특정 태그 지정 (예: `:latest` 대신 `:v1.2.3`)\n"
                    analysis += "- 이미지 버전을 명시하여 재현 가능한 배포 보장\n"
                else:
                    analysis += "- 해당 설정을 보안 모범 사례에 따라 수정\n"
                    analysis += "- Kubernetes 보안 컨텍스트 가이드라인 준수\n"
                analysis += "\n---\n\n"
            
            if len(medium_vulns) > 3:
                analysis += f"**... 및 {len(medium_vulns) - 3}개 더**\n\n"
    
    # IaC 스캔 분석
    if "error" not in trivy_iac and trivy_iac.get("total_vulnerabilities", 0) > 0:
        analysis += "## 🏗️ **Infrastructure as Code (IaC) 분석**\n\n"
        analysis += "### 📋 IaC란?\n\n"
        analysis += "Infrastructure as Code는 **인프라 구성을 코드로 관리**하는 방식입니다.\n\n"
        analysis += "**주요 검사 대상**:\n"
        analysis += "- ☁️ **Terraform 파일**: AWS, Azure, GCP 등 클라우드 인프라 설정\n"
        analysis += "- 🔧 **CloudFormation**: AWS 리소스 템플릿\n"
        analysis += "- 🐳 **Docker Compose**: 컨테이너 오케스트레이션 설정\n"
        analysis += "- 📋 **Ansible Playbooks**: 서버 구성 자동화 스크립트\n\n"
        
        # 심각도별 분류
        high_vulns = [v for v in trivy_iac.get("all_vulnerabilities", []) if v['severity'] == 'error']
        medium_vulns = [v for v in trivy_iac.get("all_vulnerabilities", []) if v['severity'] == 'warning']
        low_vulns = [v for v in trivy_iac.get("all_vulnerabilities", []) if v['severity'] == 'note']
        
        # 통계 테이블 (조치 필요성 컬럼 추가)
        analysis += "### 📊 IaC 구성 통계\n\n"
        analysis += "| 심각도 | 개수 | 상태 | 조치 필요성 |\n"
        analysis += "|--------|------|------|-------------|\n"
        analysis += f"| 🔴 높음 | {len(high_vulns)}개 | {'❌ 위험' if len(high_vulns) > 0 else '✅ 양호'} | 즉시 조치 |\n"
        analysis += f"| 🟡 중간 | {len(medium_vulns)}개 | {'⚠️ 주의' if len(medium_vulns) > 0 else '✅ 양호'} | 계획적 조치 |\n"
        analysis += f"| 🟢 낮음 | {len(low_vulns)}개 | {'ℹ️ 정보' if len(low_vulns) > 0 else '✅ 양호'} | 모니터링 |\n\n"
        
        if high_vulns:
            analysis += "### 🔴 **높은 심각도 문제 (즉시 조치 필요)**\n\n"
            for i, vuln in enumerate(high_vulns[:5], 1):
                analysis += f"#### {i}. **{vuln['rule_id']}**\n\n"
                analysis += f"**📍 위치**: `{vuln['location']}`\n\n"
                analysis += f"**📝 문제 설명**:\n{translate_vulnerability_message(vuln['rule_id'], vuln['message'])}\n\n"
                analysis += f"**🚨 해킹 시나리오**:\n{get_hacking_scenario(vuln['rule_id'], vuln['message'])}\n\n"
                analysis += "**🔗 관련 링크**: [자세한 정보](https://avd.aquasec.com/misconfig/" + vuln['rule_id'].lower() + ")\n\n"
                analysis += "**🛠️ 조치 방법**:\n"
                
                if "IMDS" in vuln['message']:
                    analysis += "- EC2 인스턴스 설정에 `metadata_options.http_tokens = \"required\"` 추가\n"
                    analysis += "- IMDSv2를 강제하여 보안 강화\n"
                elif "HTTPS" in vuln['message']:
                    analysis += "- 로드 밸런서 리스너를 HTTPS로 변경\n"
                    analysis += "- SSL/TLS 인증서 설정 및 적용\n"
                elif "encryption" in vuln['message']:
                    analysis += "- RDS 인스턴스에 `storage_encrypted = true` 설정\n"
                    analysis += "- KMS 키를 지정하여 데이터 암호화 강화\n"
                elif "unrestricted egress" in vuln['message']:
                    analysis += "- 보안 그룹 규칙에서 `0.0.0.0/0` 대신 필요한 IP 범위만 허용\n"
                    analysis += "- 네트워크 접근을 최소화하여 보안 강화\n"
                else:
                    analysis += "- 해당 인프라 설정을 보안 모범 사례에 따라 수정\n"
                    analysis += "- AWS 보안 모범 사례 가이드라인 준수\n"
                analysis += "\n---\n\n"
            
            if len(high_vulns) > 5:
                analysis += f"**... 및 {len(high_vulns) - 5}개 더**\n\n"
    
    # 런타임 이벤트 분석
    if runtime_events and runtime_events.get("total", 0) > 0:
        analysis += "## ⚡ **Runtime Layer (런타임 계층) 분석**\n\n"
        analysis += "### 📋 런타임 계층이란?\n\n"
        analysis += "런타임 계층은 **실제로 시스템이 실행되는 동안** 발생하는 보안 위협을 실시간으로 감지하는 계층입니다.\n\n"
        analysis += "**주요 검사 대상**:\n"
        analysis += "- 🐳 **실행 중인 컨테이너**: 컨테이너 내부의 보안 이벤트\n"
        analysis += "- 🔍 **애플리케이션 동작**: 앱의 비정상적인 행동 패턴\n"
        analysis += "- 🌐 **네트워크 트래픽**: 의심스러운 네트워크 통신\n"
        analysis += "- 📊 **시스템 리소스**: CPU, 메모리, 디스크 사용량 이상\n\n"
        
        analysis += f"### 📊 런타임 이벤트 통계\n\n"
        analysis += f"- **총 이벤트 수**: **{runtime_events['total']}개**\n"
        analysis += f"- **상태**: {'🔴 위험' if runtime_events['total'] > 0 else '🟢 양호'}\n\n"
        
        if runtime_events.get("events"):
            analysis += "### 🔍 **발견된 런타임 이벤트**\n\n"
            for i, event in enumerate(runtime_events['events'][:3], 1):
                analysis += f"#### {i}. **{event['rule_id']}**\n\n"
                analysis += f"**📝 이벤트 내용**:\n{event['message']}\n\n"
                analysis += f"**⚠️ 심각도**: {event['severity']}\n\n"
                analysis += f"**📍 위치**: {event['location']}\n\n"
                analysis += "**🛠️ 조치 방법**:\n"
                analysis += "- 해당 컨테이너 이미지를 최신 보안 패치가 적용된 버전으로 업데이트\n"
                analysis += "- 런타임 보안 모니터링 강화\n"
                analysis += "- 정기적인 컨테이너 이미지 스캔 수행\n\n"
                analysis += "---\n\n"
    
    # 정책 위반 분석
    if policy_violations and policy_violations.get("total", 0) > 0:
        analysis += "## 📋 **Policy Layer (정책 계층) 분석**\n\n"
        analysis += "### 📋 정책 계층이란?\n\n"
        analysis += "정책 계층은 **조직의 보안 정책을 자동으로 적용**하고 위반 사항을 차단하는 계층입니다.\n\n"
        analysis += "**주요 검사 대상**:\n"
        analysis += "- 🚫 **리소스 생성/수정**: Kubernetes 리소스 생성 시 정책 준수 여부\n"
        analysis += "- 🔒 **접근 제어**: 사용자 권한 및 역할 기반 접근 제어\n"
        analysis += "- 📋 **정책 위반**: 조직 보안 정책 위반 사항\n"
        analysis += "- ⚠️ **자동 차단**: 정책 위반 시 자동 차단 및 알림\n\n"
        
        analysis += f"### 📊 정책 위반 통계\n\n"
        analysis += f"- **총 위반 수**: **{policy_violations['total']}개**\n"
        analysis += f"- **상태**: {'🔴 위험' if policy_violations['total'] > 0 else '🟢 양호'}\n\n"
        
        if policy_violations.get("by_kind"):
            analysis += "### 📈 **리소스 종류별 위반 현황**\n\n"
            for kind, count in policy_violations["by_kind"].items():
                analysis += f"- **{kind}**: {count}개\n"
            analysis += "\n"
        
        analysis += "### 🛠️ **조치 방법**:\n\n"
        analysis += "1. **위반된 리소스 수정**: 정책에 맞게 리소스 설정을 수정\n"
        analysis += "2. **정책 검토**: 정책이 너무 엄격하다면 정책 자체를 검토\n"
        analysis += "3. **알림 설정**: 정책 위반에 대한 자동 알림 설정\n"
        analysis += "4. **팀 교육**: 정책 준수에 대한 팀 교육 실시\n\n"
    
    # 종합 보안 권장사항
    analysis += "## 🛡️ **종합 보안 권장사항 및 조치 계획**\n\n"
    analysis += f"현재 시스템의 **🔴 위험** 상태를 강조합니다.\n\n"
    
    if high_count > 0:
        analysis += f"### 🔴 **즉시 조치 필요 (우선순위 1)**\n"
        analysis += f"- **대상**: {high_count}개의 높은 심각도 문제\n"
        analysis += f"- **목표**: 보안 위험을 즉시 제거하여 시스템 보호\n"
        analysis += f"- **실행 방안**:\n"
        analysis += f"  - 높은 심각도 문제를 우선적으로 해결\n"
        analysis += f"  - 즉시 수정 가능한 설정 변경\n"
        analysis += f"  - 긴급 보안 패치 적용\n\n"
    
    if medium_count > 0:
        analysis += f"### 🟡 **계획적 조치 필요 (우선순위 2)**\n"
        analysis += f"- **대상**: {medium_count}개의 중간 심각도 문제\n"
        analysis += f"- **목표**: 단계별 접근으로 안정적인 보안 강화\n"
        analysis += f"- **실행 방안**:\n"
        analysis += f"  - 해결 계획 수립 및 일정 관리\n"
        analysis += f"  - 단계별 보안 개선 작업\n"
        analysis += f"  - 정기적인 진행 상황 점검\n\n"
    
    analysis += "### 🟢 **지속적 개선 및 모니터링 (우선순위 3)**\n"
    analysis += "- **대상**: 전체 보안 시스템 및 프로세스\n"
    analysis += "- **목표**: 지속적인 보안 강화 및 위험 예방\n"
    analysis += "- **실행 방안**:\n"
    analysis += "  - 자동화된 보안 스캔을 CI/CD 파이프라인에 통합\n"
    analysis += "  - 정기적인 보안 교육을 통한 팀 보안 인식 향상\n"
    analysis += "  - 보안 정책 수립 및 명확한 문서화\n"
    analysis += "  - 모니터링 및 알림 시스템 구축\n\n"
    
    return analysis

def main():
    """3계층 보안 모델 기반 AI 보고서 생성을 위한 메인 함수입니다."""
    print("🔍 3계층 보안 스캔 결과를 분석하고 AI 보고서를 생성합니다...")
    
    # Configuration Layer - Trivy 스캔 결과 파싱 (현재 디렉토리에서)
    trivy_fs_results = parse_sarif_file("trivy-k8s-results.sarif")
    trivy_iac_results = parse_sarif_file("trivy-iac-results.sarif")
    trivy_config_results = parse_sarif_file("trivy-k8s-results.sarif")
    trivy_image_results = parse_sarif_file("trivy-image-results.sarif")
    
    # Runtime Layer - 런타임 이벤트 파싱
    runtime_events = parse_runtime_events("runtime-events.json")
    
    # Policy Layer - 정책 위반 파싱
    policy_violations = parse_policy_violations("gatekeeper-violations.log", "gatekeeper-all-constraints.json")
    
    # AI 기반 보고서 생성 (3계층 통합)
    report_content = generate_ai_report(
        trivy_fs_results, 
        trivy_iac_results, 
        trivy_config_results, 
        trivy_image_results, 
        runtime_events, 
        policy_violations
    )
    
    # 보고서 파일에 저장
    output_file = "ai-3layer-security-report.md"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    # 통계 출력
    total_vulns = 0
    if "error" not in trivy_fs_results:
        total_vulns += trivy_fs_results.get("total_vulnerabilities", 0)
    if "error" not in trivy_iac_results:
        total_vulns += trivy_iac_results.get("total_vulnerabilities", 0)
    if trivy_config_results and "error" not in trivy_config_results:
        total_vulns += trivy_config_results.get("total_vulnerabilities", 0)
    if trivy_image_results and "error" not in trivy_image_results:
        total_vulns += trivy_image_results.get("total_vulnerabilities", 0)
    
    print(f"✅ AI 3계층 보안 종합 보고서 생성 완료: {output_file}")
    print(f"📊 Configuration Layer 취약점: {total_vulns}개")
    print(f"🔍 Runtime Layer 이벤트: {runtime_events.get('total', 0)}개")
    print(f"🔒 Policy Layer 위반: {policy_violations.get('total', 0)}개")
    
    if total_vulns == 0 and runtime_events.get('total', 0) == 0 and policy_violations.get('total', 0) == 0:
        print("🎉 3계층 보안 스캔 결과: 모든 계층에서 문제가 발견되지 않았습니다!")
    else:
        print("⚠️  발견된 보안 문제를 검토하고 조치하시기 바랍니다.")
        print("📋 상세한 조치 방법은 보고서를 참고하세요.")

if __name__ == "__main__":
    main() 