import json
from datetime import datetime
from typing import List, Dict, Optional



def generate_final_report(
    vuln_list: List[Dict], 
    target_system: str = "웹 애플리케이션",
    image_filename: str = "unknown.jpg",
    author: str = "보안진단팀"
) -> str:
    """
    Vision-LLM으로 분석된 취약점 데이터를 바탕으로 최종 Markdown 보고서를 생성합니다.
    
    Args:
        vuln_list: 취약점 분석 결과 JSON 배열
        target_system: 대상 시스템명
        image_filename: 원본 진단 이미지 파일명
        author: 보고서 작성자/팀
    
    Returns:
        str: Markdown 형식의 최종 보고서
    """
    
    if not vuln_list:
        return "# ❌ 취약점 데이터가 없습니다.\n\n분석할 취약점이 발견되지 않았습니다."
    
    today = datetime.now().strftime("%Y-%m-%d")
    
    # 1. 보고서 개요
    report = f"""# ▶ 웹 취약점 종합 보고서

## 1. 보고서 개요

* **작성일**: {today}
* **작성자/팀**: {author}
* **대상 시스템**: {target_system}
* **진단 이미지**: {image_filename}
* **보고 목적**: 진단된 취약점을 통해 조직원의 보안정책 준수 의지를 강화하고, 보호동기 이론(PMT) 기반 실행 전략을 제시

### 📸 취약점 진단 이미지

![취약점 진단 결과](/uploads/{image_filename})

*이미지에서 발견된 취약점들을 AI가 분석하여 본 보고서를 생성했습니다.*

---

## 2. 취약점 요약 Table (OWASP Top 10 기준)

| OWASP 카테고리 | 취약점 유형 | CVE/CWE |
| ------------ | -------- | ------- |
"""
    
    # 2. 취약점 요약 테이블 - OWASP 기준으로 재구성
    for i, vuln in enumerate(vuln_list, 1):
        # 이미지에서 읽어온 실제 데이터 사용
        vuln_type = vuln.get('type', '알 수 없는 취약점')
        
        # OWASP Top 10 카테고리 매핑
        vuln_type_lower = vuln_type.lower()
        if any(keyword in vuln_type_lower for keyword in ['sql injection', '인젝션', 'sql']):
            owasp_category = "A03:2021 - Injection"
            cve_cwe = "CWE-89"
        elif any(keyword in vuln_type_lower for keyword in ['xss', '크로스사이트', '스크립트']):
            owasp_category = "A03:2021 - Injection"
            cve_cwe = "CWE-79"
        elif any(keyword in vuln_type_lower for keyword in ['csrf', '위조', '요청']):
            owasp_category = "A01:2021 - Broken Access Control"
            cve_cwe = "CWE-352"
        elif any(keyword in vuln_type_lower for keyword in ['인증', 'authentication', '로그인']):
            owasp_category = "A07:2021 - Identification and Authentication Failures"
            cve_cwe = "CWE-287"
        elif any(keyword in vuln_type_lower for keyword in ['세션', 'session']):
            owasp_category = "A02:2021 - Cryptographic Failures"
            cve_cwe = "CWE-384"
        elif any(keyword in vuln_type_lower for keyword in ['업로드', '파일', 'file upload']):
            owasp_category = "A05:2021 - Security Misconfiguration"
            cve_cwe = "CWE-434"
        elif any(keyword in vuln_type_lower for keyword in ['경로', '순회', 'path traversal']):
            owasp_category = "A01:2021 - Broken Access Control"
            cve_cwe = "CWE-22"
        elif any(keyword in vuln_type_lower for keyword in ['정보', '노출', 'information disclosure']):
            owasp_category = "A05:2021 - Security Misconfiguration"
            cve_cwe = "CWE-200"
        elif any(keyword in vuln_type_lower for keyword in ['설정', 'configuration', '보안']):
            owasp_category = "A05:2021 - Security Misconfiguration"
            cve_cwe = "CWE-16"
        else:
            owasp_category = "기타 취약점"
            cve_cwe = "N/A"
        
        report += f"| {owasp_category} | {vuln_type} | {cve_cwe} |\n"
    
    report += "\n---\n\n## 3. 취약점별 위험성 및 유사 해킹 사고 사례\n\n"
    report += "각 취약점에 대해 \"위험성(5줄 이상)\"과 \"유사 해킹 사고 사례(1건, 5줄 이상)\"를 한 묶음으로 정리했습니다.\n\n"
    
    # 3. 취약점별 위험성 및 유사 해킹 사고 사례
    for vuln in vuln_list:
        vuln_type = vuln.get('type', 'N/A')
        report += f"### {vuln_type}\n\n"
        
        # 위험성
        report += "**위험성**\n"
        risk = vuln.get('risk', '위험성 정보가 없습니다.')
        report += f"{risk}\n\n"
        
        # 유사 해킹 사고 사례
        report += "**유사 해킹 사고 사례**\n"
        incidents = vuln.get('incidents', [])
        if incidents:
            incident = incidents[0]  # 첫 번째 사례만 사용
            report += f"**{incident.get('name', 'N/A')} ({incident.get('date', 'N/A')})**\n"
            report += f"{incident.get('summary', '피해 요약 정보가 없습니다.')}\n\n"
        else:
            report += "관련 사고 사례 정보가 없습니다.\n\n"
        
        report += "---\n\n"
    
    report += "## 4. 경영진 보고사항 (Management Brief)\n\n"
    
    # 취약점 데이터 분석
    total_vulns = len(vuln_list)
    high_severity_count = len([v for v in vuln_list if v.get('severity') == '높음'])
    medium_severity_count = len([v for v in vuln_list if v.get('severity') == '중간'])
    vuln_types = [v.get('type', '') for v in vuln_list if v.get('type')]
    
    # 취약점 유형별 분석
    auth_vulns = [v for v in vuln_types if any(keyword in v.lower() for keyword in ['인증', '로그인', '세션', '권한', 'sql', '인젝션'])]
    upload_vulns = [v for v in vuln_types if any(keyword in v.lower() for keyword in ['업로드', '파일', '경로', '순회'])]
    xss_vulns = [v for v in vuln_types if any(keyword in v.lower() for keyword in ['xss', '스크립트', '크로스사이트'])]
    info_vulns = [v for v in vuln_types if any(keyword in v.lower() for keyword in ['정보', '누출', '노출', '디버그', '에러'])]
    
    if vuln_types:
        # 1. 전체 위험성 평가
        report += "### 1️⃣ 전체 위험성 평가\n\n"
        
        # OWASP Top 10 2021 기준으로 위험성 등급 평가
        owasp_vulns = []
        owasp_categories = {
            'A01:2021-Broken Access Control': [],
            'A02:2021-Cryptographic Failures': [],
            'A03:2021-Injection': [],
            'A04:2021-Insecure Design': [],
            'A05:2021-Security Misconfiguration': [],
            'A06:2021-Vulnerable and Outdated Components': [],
            'A07:2021-Identification and Authentication Failures': [],
            'A08:2021-Software and Data Integrity Failures': [],
            'A09:2021-Security Logging and Monitoring Failures': [],
            'A10:2021-Server-Side Request Forgery (SSRF)': []
        }
        
        for vuln in vuln_list:
            vuln_type = vuln.get('type', '').lower()
            module = vuln.get('module', '')
            
            # OWASP Top 10 2021 기준 정확한 분류
            if any(keyword in vuln_type for keyword in ['sql injection', '인젝션', 'nosql injection', 'ldap injection']):
                owasp_categories['A03:2021-Injection'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
            elif any(keyword in vuln_type for keyword in ['xss', '크로스사이트', 'cross-site scripting']):
                owasp_categories['A03:2021-Injection'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
            elif any(keyword in vuln_type for keyword in ['경로 순회', 'path traversal', 'directory traversal']):
                owasp_categories['A01:2021-Broken Access Control'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
            elif any(keyword in vuln_type for keyword in ['파일 업로드', 'file upload', 'unrestricted file upload']):
                owasp_categories['A01:2021-Broken Access Control'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
            elif any(keyword in vuln_type for keyword in ['인증', 'authentication', '로그인', 'login', '세션', 'session']):
                owasp_categories['A07:2021-Identification and Authentication Failures'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
            elif any(keyword in vuln_type for keyword in ['csrf', 'cross-site request forgery', '사이트 간 요청 위조']):
                owasp_categories['A01:2021-Broken Access Control'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
            elif any(keyword in vuln_type for keyword in ['정보 노출', 'information disclosure', '디버그', 'debug', '에러', 'error']):
                owasp_categories['A05:2021-Security Misconfiguration'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
            elif any(keyword in vuln_type for keyword in ['설정', 'configuration', '보안 설정', 'security config']):
                owasp_categories['A05:2021-Security Misconfiguration'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
            elif any(keyword in vuln_type for keyword in ['구성요소', 'component', '라이브러리', 'library', '버전', 'version']):
                owasp_categories['A06:2021-Vulnerable and Outdated Components'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
            elif any(keyword in vuln_type for keyword in ['암호화', 'encryption', 'ssl', 'tls', 'https']):
                owasp_categories['A02:2021-Cryptographic Failures'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
            elif any(keyword in vuln_type for keyword in ['로깅', 'logging', '모니터링', 'monitoring']):
                owasp_categories['A09:2021-Security Logging and Monitoring Failures'].append(f"{vuln.get('type', '')}({module})")
                owasp_vulns.append(vuln.get('type', ''))
        
        owasp_vuln_count = len(owasp_vulns)
        
        # 위험성 등급 결정 (OWASP Top 10 기준)
        if owasp_vuln_count >= 3:
            risk_level = "🔴 **극도로 위험 (Critical Risk)**"
        elif owasp_vuln_count >= 2:
            risk_level = "🟠 **매우 위험 (High Risk)**"
        elif total_vulns >= 2:
            risk_level = "🟡 **위험 (Medium Risk)**"
        else:
            risk_level = "🟢 **낮은 위험 (Low Risk)**"
        
        # 💥 **경영진을 위한 핵심 위험 요약**
        risk_description = f"**💥 핵심 위험 요약**:\n"
        
        if owasp_vuln_count >= 3:
            risk_description += f"**🔴 즉시 대응 필요** - {total_vulns}개 취약점 중 {owasp_vuln_count}개가 세계 최고 위험 취약점\n"
        elif owasp_vuln_count >= 2:
            risk_description += f"**🟠 긴급 대응 필요** - {total_vulns}개 취약점 중 {owasp_vuln_count}개가 세계 최고 위험 취약점\n"
        elif total_vulns >= 2:
            risk_description += f"**🟡 신속 대응 필요** - {total_vulns}개 취약점 발견\n"
        else:
            risk_description += f"**🟢 점검 필요** - {total_vulns}개 취약점 발견\n"
        
        risk_description += "\n"
        
        # 🚨 **해커가 지금 당장 할 수 있는 일**
        risk_description += "**🚨 해커가 지금 당장 할 수 있는 일**:\n"
        
        # 가장 위험한 취약점 3개만 선별해서 간단하게 설명
        critical_vulns = []
        for vuln in vuln_list:
            vuln_type = vuln.get('type', '').lower()
            if any(keyword in vuln_type for keyword in ['sql injection', '인젝션', '파일 업로드', 'upload', '인증', 'authentication']):
                critical_vulns.append(vuln)
        
        if critical_vulns:
            for i, vuln in enumerate(critical_vulns[:3], 1):
                vuln_type = vuln.get('type', '')
                if 'sql' in vuln_type.lower() or '인젝션' in vuln_type.lower():
                    risk_description += f"• **{i}. 고객 데이터 훔치기** - 모든 고객 정보를 그대로 가져갈 수 있음\n"
                elif '파일' in vuln_type.lower() or 'upload' in vuln_type.lower():
                    risk_description += f"• **{i}. 서버 장악** - 웹사이트를 완전히 마비시킬 수 있음\n"
                elif '인증' in vuln_type.lower() or '로그인' in vuln_type.lower():
                    risk_description += f"• **{i}. 관리자 권한 탈취** - 회사 시스템을 마음대로 조작할 수 있음\n"
        
        if owasp_vuln_count > 0:
            risk_description += f"• **💀 초보 해커도 공격 가능** - 인터넷에 공개된 도구로 누구나 공격 가능\n\n"
        
        # 💰 **비즈니스 피해 예상**
        risk_description += "**💰 예상 비즈니스 피해**:\n"
        
        if owasp_vuln_count >= 3:
            risk_description += f"• **웹사이트 완전 마비** - 매출 100% 중단\n"
            risk_description += f"• **고객 정보 100% 유출** - 개인정보보호법 위반 과태료 + 고객 이탈\n"
            risk_description += f"• **예상 손실**: 최대 10억원 이상\n\n"
        elif owasp_vuln_count >= 2:
            risk_description += f"• **웹사이트 부분 마비** - 매출 50% 중단\n"
            risk_description += f"• **고객 정보 대부분 유출** - 법적 책임 + 평판 손상\n"
            risk_description += f"• **예상 손실**: 최대 5억원\n\n"
        elif total_vulns >= 2:
            risk_description += f"• **서비스 일시 중단** - 매출 20% 감소\n"
            risk_description += f"• **고객 신뢰도 하락** - 브랜드 이미지 손상\n"
            risk_description += f"• **예상 손실**: 최대 1억원\n\n"
        else:
            risk_description += f"• **미미한 영향** - 현재 매출에 직접적 영향 없음\n"
            risk_description += f"• **예방적 조치 권장** - 향후 보안 강화 필요\n\n"
        
        # 취약점별 위험도 점수 계산 (가장 위험한 것 우선)
        vuln_risk_scores = []
        
        for vuln in vuln_list:
            vuln_type = vuln.get('type', '').lower()
            severity = vuln.get('severity', '').lower()
            module = vuln.get('module', '')
            
            # 위험도 점수 계산 (높을수록 위험)
            risk_score = 0
            
            # 심각도별 점수
            if severity in ['높음', 'high', 'critical']:
                risk_score += 10
            elif severity in ['중간', 'medium']:
                risk_score += 5
            else:
                risk_score += 2
            
            # 취약점 유형별 점수
            if 'sql injection' in vuln_type or '인젝션' in vuln_type:
                risk_score += 15  # 가장 위험
            elif '파일 업로드' in vuln_type or 'upload' in vuln_type:
                risk_score += 12  # 서버 장악 가능
            elif '인증' in vuln_type or '로그인' in vuln_type or 'authentication' in vuln_type:
                risk_score += 10  # 권한 획득
            elif 'xss' in vuln_type or '크로스사이트' in vuln_type:
                risk_score += 8   # 사용자 정보 탈취
            elif 'csrf' in vuln_type or '사이트 간' in vuln_type:
                risk_score += 7   # 무단 작업 실행
            elif '경로 순회' in vuln_type or 'path traversal' in vuln_type:
                risk_score += 6   # 시스템 파일 접근
            elif '정보 노출' in vuln_type or 'information disclosure' in vuln_type:
                risk_score += 5   # 정보 유출
            elif '설정' in vuln_type or 'configuration' in vuln_type:
                risk_score += 4   # 보안 설정 우회
            else:
                risk_score += 3   # 일반적 위험
            
            vuln_risk_scores.append((vuln, risk_score))
        
        # 위험도 순으로 정렬 (높은 순)
        vuln_risk_scores.sort(key=lambda x: x[1], reverse=True)
        
        # 가장 위험한 취약점 3개만 선택하여 상세 설명
        top_risks = vuln_risk_scores[:3]
        
        if top_risks:
            risk_description += "**🚨 가장 위험한 비즈니스 중단 시나리오**:\n\n"
            
            for i, (vuln, score) in enumerate(top_risks, 1):
                vuln_type = vuln.get('type', '알 수 없는 취약점')
                severity = vuln.get('severity', '분석 중')
                module = vuln.get('module', '전체 시스템')
                
                risk_description += f"**{i}. {vuln_type}** (위험도: {score}점, 심각도: {severity})\n"
                risk_description += f"   - 위치: {module}\n"
                
                # 취약점별 구체적인 비즈니스 중단 시나리오
                if 'sql injection' in vuln_type.lower() or '인젝션' in vuln_type.lower():
                    risk_description += f"   - **즉시 서비스 중단**: 데이터베이스 파괴로 웹사이트 완전 마비\n"
                    risk_description += f"   - **고객 정보 100% 유출**: 개인정보, 결제정보 등 모든 데이터 탈취\n"
                    risk_description += f"   - **복구 불가능**: 백업 데이터까지 손상 가능\n"
                elif '파일 업로드' in vuln_type.lower() or 'upload' in vuln_type.lower():
                    risk_description += f"   - **서버 완전 장악**: 악성 프로그램으로 전체 시스템 제어\n"
                    risk_description += f"   - **고객 접근 차단**: 웹사이트를 랜섬웨어로 암호화\n"
                    risk_description += f"   - **비즈니스 중단**: 최소 1주일간 서비스 불가\n"
                elif '인증' in vuln_type.lower() or '로그인' in vuln_type.lower():
                    risk_description += f"   - **관리자 권한 탈취**: 모든 고객 데이터에 무단 접근\n"
                    risk_description += f"   - **시스템 설정 변경**: 보안 정책 무력화\n"
                    risk_description += f"   - **고객 신뢰도 완전 상실**: 브랜드 이미지 파괴\n"
                elif 'xss' in vuln_type.lower() or '크로스사이트' in vuln_type.lower():
                    risk_description += f"   - **고객 세션 탈취**: 개인정보 및 로그인 정보 유출\n"
                    risk_description += f"   - **피싱 공격 유발**: 고객이 악성 사이트로 유도\n"
                    risk_description += f"   - **고객 이탈**: 서비스 신뢰도 하락으로 고객 유실\n"
                elif 'csrf' in vuln_type.lower() or '사이트 간' in vuln_type.lower():
                    risk_description += f"   - **무단 거래 실행**: 고객이 모르는 사이에 원치 않는 작업 수행\n"
                    risk_description += f"   - **법적 분쟁**: 고객과의 소송 위험\n"
                    risk_description += f"   - **서비스 신뢰도 하락**: 고객 불만 증가\n"
                else:
                    risk_description += f"   - **일반적 보안 위협**: 비즈니스 연속성 저해\n"
                    risk_description += f"   - **부분적 서비스 장애**: 일부 기능 사용 불가\n"
                    risk_description += f"   - **고객 불만 증가**: 서비스 품질 저하\n"
                
                risk_description += "\n"
        
        # 💰 **비즈니스 영향도 (발견된 취약점 기반 동적 분석)**
        
        # 총 위험도 점수 계산
        total_risk_score = sum(score for _, score in vuln_risk_scores)
        
        risk_description += f"**💰 비즈니스 영향도 분석 (총 위험도: {total_risk_score}점)**:\n\n"
        
        # 발견된 취약점별 구체적인 비즈니스 영향 계산
        business_impacts = {
            'service_disruption': 0,  # 서비스 중단
            'data_breach': 0,         # 데이터 유출
            'financial_loss': 0,      # 금융 손실
            'legal_liability': 0,     # 법적 책임
            'reputation_damage': 0,   # 평판 손상
            'customer_loss': 0        # 고객 이탈
        }
        
        # 각 취약점별 비즈니스 영향 점수 계산
        for vuln, score in vuln_risk_scores:
            vuln_type = vuln.get('type', '').lower()
            module = vuln.get('module', '')
            
            # SQL 인젝션: 데이터베이스 침해로 인한 최대 피해
            if 'sql injection' in vuln_type or '인젝션' in vuln_type:
                business_impacts['service_disruption'] += 10  # 즉시 서비스 중단
                business_impacts['data_breach'] += 15        # 모든 데이터 유출
                business_impacts['financial_loss'] += 12     # 대규모 금융 손실
                business_impacts['legal_liability'] += 10    # 개인정보보호법 위반
                business_impacts['reputation_damage'] += 8   # 브랜드 파괴
                business_impacts['customer_loss'] += 10      # 고객 완전 이탈
                
            # 파일 업로드: 서버 장악으로 인한 피해
            elif '파일 업로드' in vuln_type or 'upload' in vuln_type:
                business_impacts['service_disruption'] += 12  # 서버 완전 장악
                business_impacts['data_breach'] += 10        # 서버 데이터 유출
                business_impacts['financial_loss'] += 15     # 랜섬웨어 요구
                business_impacts['legal_liability'] += 8     # 시스템 장악
                business_impacts['reputation_damage'] += 10  # 완전한 신뢰도 상실
                business_impacts['customer_loss'] += 12      # 고객 대량 이탈
                
            # 인증 우회: 관리자 권한 탈취
            elif '인증' in vuln_type or '로그인' in vuln_type or 'authentication' in vuln_type:
                business_impacts['service_disruption'] += 8   # 시스템 설정 변경
                business_impacts['data_breach'] += 12        # 모든 데이터 접근
                business_impacts['financial_loss'] += 10     # 무단 거래 실행
                business_impacts['legal_liability'] += 12    # 관리자 권한 악용
                business_impacts['reputation_damage'] += 10  # 브랜드 이미지 파괴
                business_impacts['customer_loss'] += 10      # 고객 신뢰도 상실
                
            # XSS: 사용자 정보 탈취
            elif 'xss' in vuln_type or '크로스사이트' in vuln_type:
                business_impacts['service_disruption'] += 3   # 부분적 서비스 장애
                business_impacts['data_breach'] += 8         # 사용자 개인정보 유출
                business_impacts['financial_loss'] += 6      # 고객 피해 보상
                business_impacts['legal_liability'] += 8     # 개인정보 유출
                business_impacts['reputation_damage'] += 6   # 서비스 신뢰도 하락
                business_impacts['customer_loss'] += 8       # 고객 이탈
                
            # CSRF: 무단 작업 실행
            elif 'csrf' in vuln_type or '사이트 간' in vuln_type:
                business_impacts['service_disruption'] += 2   # 기능 오작동
                business_impacts['data_breach'] += 5         # 제한적 정보 유출
                business_impacts['financial_loss'] += 8      # 무단 거래로 인한 손실
                business_impacts['legal_liability'] += 6     # 무단 작업 실행
                business_impacts['reputation_damage'] += 5   # 서비스 신뢰도 하락
                business_impacts['customer_loss'] += 6       # 고객 불만 증가
                
            # 기타 취약점
            else:
                business_impacts['service_disruption'] += 2
                business_impacts['data_breach'] += 3
                business_impacts['financial_loss'] += 3
                business_impacts['legal_liability'] += 3
                business_impacts['reputation_damage'] += 3
                business_impacts['customer_loss'] += 3
        
        # 비즈니스 영향도 등급 결정
        max_impact = max(business_impacts.values())
        
        if max_impact >= 40:
            risk_description += f"**💀 극도로 위험한 비즈니스 영향**:\n"
            risk_description += f"• **서비스 중단**: {business_impacts['service_disruption']}점 - 즉시 웹사이트 마비\n"
            risk_description += f"• **데이터 유출**: {business_impacts['data_breach']}점 - 고객 정보 100% 노출\n"
            risk_description += f"• **금융 손실**: {business_impacts['financial_loss']}점 - 최대 3억원 손실 예상\n"
            risk_description += f"• **법적 책임**: {business_impacts['legal_liability']}점 - 개인정보보호법 위반 과태료\n"
            risk_description += f"• **평판 손상**: {business_impacts['reputation_damage']}점 - 브랜드 완전 파괴\n"
            risk_description += f"• **고객 이탈**: {business_impacts['customer_loss']}점 - 고객 100% 이탈\n\n"
            
        elif max_impact >= 25:
            risk_description += f"**🚨 매우 위험한 비즈니스 영향**:\n"
            risk_description += f"• **서비스 장애**: {business_impacts['service_disruption']}점 - 일부 기능 마비\n"
            risk_description += f"• **데이터 유출**: {business_impacts['data_breach']}점 - 대부분 고객 정보 노출\n"
            risk_description += f"• **금융 손실**: {business_impacts['financial_loss']}점 - 최대 1억원 손실 예상\n"
            risk_description += f"• **법적 책임**: {business_impacts['legal_liability']}점 - 관련 법규 위반\n"
            risk_description += f"• **평판 손상**: {business_impacts['reputation_damage']}점 - 브랜드 심각한 손상\n"
            risk_description += f"• **고객 이탈**: {business_impacts['customer_loss']}점 - 고객 50-80% 이탈\n\n"
            
        elif max_impact >= 15:
            risk_description += f"**⚠️ 위험한 비즈니스 영향**:\n"
            risk_description += f"• **서비스 장애**: {business_impacts['service_disruption']}점 - 부분적 기능 오작동\n"
            risk_description += f"• **데이터 유출**: {business_impacts['data_breach']}점 - 일부 정보 노출 위험\n"
            risk_description += f"• **금융 손실**: {business_impacts['financial_loss']}점 - 최대 3천만원 손실 예상\n"
            risk_description += f"• **법적 책임**: {business_impacts['legal_liability']}점 - 규제 위반 가능성\n"
            risk_description += f"• **평판 손상**: {business_impacts['reputation_damage']}점 - 서비스 신뢰도 하락\n"
            risk_description += f"• **고객 이탈**: {business_impacts['customer_loss']}점 - 고객 10-30% 이탈\n\n"
            
        else:
            risk_description += f"**🟢 낮은 비즈니스 영향**:\n"
            risk_description += f"• **서비스 영향**: {business_impacts['service_disruption']}점 - 미미한 영향\n"
            risk_description += f"• **데이터 보호**: {business_impacts['data_breach']}점 - 안전함\n"
            risk_description += f"• **금융 안정**: {business_impacts['financial_loss']}점 - 직접적 손실 없음\n"
            risk_description += f"• **법적 안전**: {business_impacts['legal_liability']}점 - 규제 준수\n"
            risk_description += f"• **평판 유지**: {business_impacts['reputation_damage']}점 - 브랜드 안전\n"
            risk_description += f"• **고객 유지**: {business_impacts['customer_loss']}점 - 고객 이탈 없음\n\n"
        
        # 구체적인 피해 예상 금액
        total_financial_impact = business_impacts['financial_loss'] * 1000000  # 백만원 단위
        risk_description += f"**💰 예상 피해 금액**: 약 {total_financial_impact:,}원\n"
        risk_description += f"**📊 영향 지속 기간**: {max(1, total_risk_score // 10)}개월\n"
        risk_description += f"**🎯 복구 필요 기간**: {max(3, total_risk_score // 5)}개월\n\n"
        
        # 🎯 **해커 입장에서 본 실제 해킹 시나리오**
        risk_description += "**🎯 해커 입장에서 본 실제 해킹 시나리오**:\n"
        
        # 해커가 실제로 할 수 있는 단계별 공격 시나리오
        if total_vulns >= 3:
            risk_description += f"**🔴 해커의 완벽한 침입 시나리오 ({total_vulns}개 취약점 활용)**:\n\n"
            
            # 1단계: 초기 침입
            first_vuln = vuln_list[0]
            first_type = first_vuln.get('type', '알 수 없는 취약점')
            first_module = first_vuln.get('module', '시스템')
            
            risk_description += f"**1단계: 초기 침입**\n"
            if 'sql injection' in first_type.lower() or '인젝션' in first_type.lower():
                risk_description += f"• 해커가 {first_module}에서 SQL 인젝션을 이용해 데이터베이스에 직접 접근\n"
                risk_description += f"• 고객 정보, 관리자 계정, 비밀번호 해시 등을 모두 탈취\n"
            elif '파일 업로드' in first_type.lower() or 'upload' in first_type.lower():
                risk_description += f"• 해커가 {first_module}에서 악성 파일을 업로드하여 서버에 웹쉘 설치\n"
                risk_description += f"• 서버에 원격 접근 권한을 획득\n"
            elif '인증' in first_type.lower() or '로그인' in first_type.lower():
                risk_description += f"• 해커가 {first_module}에서 인증 우회를 통해 관리자 계정으로 로그인\n"
                risk_description += f"• 시스템의 모든 권한을 획득\n"
            else:
                risk_description += f"• 해커가 {first_module}에서 {first_type} 취약점을 이용해 시스템에 침입\n"
                risk_description += f"• 초기 접근 권한을 획득\n"
            
            # 2단계: 권한 확장
            if len(vuln_list) >= 2:
                second_vuln = vuln_list[1]
                second_type = second_vuln.get('type', '알 수 없는 취약점')
                second_module = second_vuln.get('module', '시스템')
                
                risk_description += f"\n**2단계: 권한 확장**\n"
                if 'xss' in second_type.lower() or '크로스사이트' in second_type.lower():
                    risk_description += f"• 해커가 {second_module}에서 XSS를 이용해 관리자 세션을 탈취\n"
                    risk_description += f"• 관리자 권한으로 시스템 전체에 접근 가능\n"
                elif '경로 순회' in second_type.lower() or 'path traversal' in second_type.lower():
                    risk_description += f"• 해커가 {second_module}에서 경로 순회를 이용해 시스템 파일에 접근\n"
                    risk_description += f"• 설정 파일, 로그 파일 등을 탈취하여 더 많은 정보 수집\n"
                elif '정보 노출' in second_type.lower():
                    risk_description += f"• 해커가 {second_module}에서 노출된 정보를 이용해 시스템 구조 파악\n"
                    risk_description += f"• 다음 공격을 위한 정보를 수집\n"
                else:
                    risk_description += f"• 해커가 {second_module}에서 {second_type} 취약점을 이용해 권한을 확장\n"
                    risk_description += f"• 더 높은 권한을 획득\n"
            
            # 3단계: 데이터 탈취
            if len(vuln_list) >= 3:
                third_vuln = vuln_list[2]
                third_type = third_vuln.get('type', '알 수 없는 취약점')
                third_module = third_vuln.get('module', '시스템')
                
                risk_description += f"\n**3단계: 데이터 탈취**\n"
                if 'csrf' in third_type.lower() or '사이트 간' in third_type.lower():
                    risk_description += f"• 해커가 {third_module}에서 CSRF를 이용해 고객 계정으로 무단 거래 실행\n"
                    risk_description += f"• 고객의 돈을 해커 계좌로 이체\n"
                elif '설정' in third_type.lower() or 'configuration' in third_type.lower():
                    risk_description += f"• 해커가 {third_module}에서 설정 오류를 이용해 보안 정책 무력화\n"
                    risk_description += f"• 백도어를 설치하여 지속적인 접근 확보\n"
                else:
                    risk_description += f"• 해커가 {third_module}에서 {third_type} 취약점을 이용해 최종 데이터 탈취\n"
                    risk_description += f"• 모든 고객 정보와 비즈니스 데이터를 외부로 유출\n"
            
            # 결과
            risk_description += f"\n**💀 최종 결과**\n"
            risk_description += f"• **시스템 완전 장악**: 해커가 웹사이트를 완전히 제어\n"
            risk_description += f"• **고객 정보 100% 유출**: 개인정보, 결제정보, 비즈니스 데이터 모두 탈취\n"
            risk_description += f"• **서비스 중단**: 웹사이트를 랜섬웨어로 암호화하여 접근 차단\n"
            risk_description += f"• **고객 피해**: 고객들의 개인정보가 다크웹에 판매됨\n"
            risk_description += f"• **회사 파산**: 법적 책임과 고객 이탈로 인한 비즈니스 파괴\n\n"
            
        elif total_vulns >= 2:
            risk_description += f"**🟠 해커의 부분적 침입 시나리오 ({total_vulns}개 취약점 활용)**:\n\n"
            
            # 2개 취약점 시나리오
            first_vuln = vuln_list[0]
            second_vuln = vuln_list[1]
            
            risk_description += f"**1단계: {first_vuln.get('type', '취약점')}을 이용한 침입**\n"
            risk_description += f"• 해커가 {first_vuln.get('module', '시스템')}에서 {first_vuln.get('type', '취약점')} 발견\n"
            risk_description += f"• 자동화 도구를 이용해 쉽게 시스템에 침입\n\n"
            
            risk_description += f"**2단계: {second_vuln.get('type', '취약점')}을 이용한 확장**\n"
            risk_description += f"• 해커가 {second_vuln.get('module', '시스템')}에서 {second_vuln.get('type', '취약점')} 발견\n"
            risk_description += f"• 첫 번째 취약점과 연계하여 더 큰 피해 발생\n\n"
            
            risk_description += f"**⚠️ 예상 결과**\n"
            risk_description += f"• **부분적 데이터 유출**: 일부 고객 정보가 탈취됨\n"
            risk_description += f"• **서비스 장애**: 일부 기능이 정상 작동하지 않음\n"
            risk_description += f"• **고객 불만**: 서비스 품질 저하로 고객 이탈\n\n"
            
        else:
            # 단일 취약점 시나리오
            single_vuln = vuln_list[0]
            vuln_type = single_vuln.get('type', '알 수 없는 취약점')
            module = single_vuln.get('module', '시스템')
            
            risk_description += f"**🟡 해커의 단일 취약점 공격 시나리오**:\n\n"
            risk_description += f"**해커의 공격 과정**\n"
            risk_description += f"• 해커가 {module}에서 {vuln_type} 취약점을 발견\n"
            risk_description += f"• 인터넷에서 쉽게 구할 수 있는 공격 도구를 다운로드\n"
            risk_description += f"• 몇 분 만에 자동화된 공격을 실행\n"
            risk_description += f"• 취약점을 성공적으로 악용하여 시스템에 침입\n\n"
            
            risk_description += f"**⚠️ 예상 결과**\n"
            risk_description += f"• **제한적 피해**: 단일 취약점으로 인한 제한적 영향\n"
            risk_description += f"• **조기 발견 가능**: 빠른 대응으로 피해 최소화 가능\n"
            risk_description += f"• **학습 기회**: 보안 강화를 위한 교훈 제공\n\n"
        
        risk_description += "\n"
        
        # 💰 **비즈니스 영향도 (구체적 피해 규모)**
        if owasp_vuln_count >= 3:
            business_impact = f"""
**💰 예상 피해 규모 (극도로 위험)**:
• **즉시 대응 필요**: 24시간 내 해킹 공격 가능성 매우 높음
• **서비스 중단**: 최대 1주일간 웹사이트 접근 불가
• **데이터 유출**: 고객 정보 100% 노출 위험
• **법적 책임**: 개인정보보호법 위반으로 최대 3억원 과태료
• **매출 손실**: 월 매출의 50-80% 감소 예상
• **브랜드 손상**: 고객 신뢰도 회복에 최소 6개월 소요
• **복구 비용**: 시스템 재구축 및 보안 강화에 5천만원 이상"""
        elif owasp_vuln_count >= 2:
            business_impact = f"""
**💰 예상 피해 규모 (매우 위험)**:
• **단기 대응 필요**: 1주일 내 해킹 공격 가능성 높음
• **서비스 장애**: 최대 3일간 일부 기능 사용 불가
• **데이터 유출**: 고객 정보 일부 노출 위험
• **법적 책임**: 개인정보보호법 위반으로 최대 1억원 과태료
• **매출 손실**: 월 매출의 20-40% 감소 예상
• **고객 이탈**: 기존 고객의 10-20% 이탈 가능성
• **복구 비용**: 보안 강화 및 시스템 수정에 2천만원 이상"""
        elif total_vulns >= 2:
            business_impact = f"""
**💰 예상 피해 규모 (위험)**:
• **중기 대응 필요**: 1개월 내 해킹 공격 가능성 있음
• **부분적 장애**: 일부 기능이 간헐적으로 오작동
• **제한적 노출**: 일부 비즈니스 정보 유출 위험
• **규제 위반**: 관련 법규 위반으로 최대 3천만원 과태료
• **매출 영향**: 월 매출의 5-15% 감소 예상
• **고객 불만**: 서비스 품질 저하로 고객 만족도 하락
• **개선 비용**: 보안 취약점 수정에 5백만원 이상"""
        else:
            business_impact = f"""
**💰 예상 피해 규모 (낮은 위험)**:
• **정기적 점검**: 3개월 내 보안 점검 권장
• **미미한 영향**: 현재 비즈니스 운영에 직접적 영향 없음
• **예방적 조치**: 향후 보안 강화를 위한 개선 권장
• **최소 비용**: 보안 개선에 1백만원 이하 예상"""
        
        report += f"**위험성 등급**: {risk_level}\n\n"
        report += f"**위험성 등급 분류 범례 (OWASP Top 10 기준)**:\n"
        report += f"* 🔴 **극도로 위험 (Critical Risk)**: OWASP Top 10 취약점 3개 이상\n"
        report += f"* 🟠 **매우 위험 (High Risk)**: OWASP Top 10 취약점 2개 이상\n"
        report += f"* 🟡 **위험 (Medium Risk)**: 총 취약점 2개 이상\n"
        report += f"* 🟢 **낮은 위험 (Low Risk)**: 총 취약점 1개 이하\n\n"
        
        report += f"**현재 위험성 등급 판단 근거**:\n"
        if owasp_vuln_count >= 3:
            report += f"* 극도로 위험: OWASP Top 10 취약점 {owasp_vuln_count}개 발견\n"
        elif owasp_vuln_count >= 2:
            report += f"* 매우 위험: OWASP Top 10 취약점 {owasp_vuln_count}개 발견\n"
        elif total_vulns >= 2:
            report += f"* 위험: 총 취약점 {total_vulns}개 발견\n"
        else:
            report += f"* 낮은 위험: 총 취약점 {total_vulns}개 발견\n"
        
        report += f"\n**📋 위험성 등급 판단 기준 (쉽게 이해하기)**:\n"
        report += f"* **🔴 극도로 위험 (3개 이상)**: 마치 집에 문이 3개나 열려있는 상황 - 도둑이 언제든 들어올 수 있음\n"
        report += f"* **🟠 매우 위험 (2개 이상)**: 집에 문이 2개 열려있는 상황 - 도둑이 쉽게 침입 가능\n"
        report += f"* **🟡 위험 (총 2개 이상)**: 집에 작은 창문이 열려있는 상황 - 도둑이 노력하면 들어올 수 있음\n"
        report += f"* **🟢 낮은 위험 (1개 이하)**: 집에 작은 틈이 있는 상황 - 대부분 안전하지만 점검이 필요\n\n"
        report += f"**💡 OWASP Top 10이란?**: 전 세계 보안 전문가들이 선정한 웹사이트에서 가장 위험한 10가지 취약점\n"
        report += f"**💡 왜 OWASP Top 10이 위험한가?**: 해커들이 가장 많이 공격하는 취약점이므로 즉시 대응이 필요\n"
        report += "\n"
        report += f"**진단 결과 요약**:\n"
        report += f"* 총 발견 취약점: {total_vulns}개\n"
        
        # 심각도별 요약 (0개인 경우 제외)
        if high_severity_count > 0:
            report += f"* 높은 심각도: {high_severity_count}개\n"
        if medium_severity_count > 0:
            report += f"* 중간 심각도: {medium_severity_count}개\n"
        
        # OWASP Top 10 2021 웹 취약점 유형별 요약 (정확한 카테고리별 분류)
        report += f"**OWASP Top 10 2021 웹 취약점**:\n"
        report += f"* A01:2021 - 접근 제어 취약점 (Broken Access Control): {len(owasp_categories['A01:2021-Broken Access Control'])}개\n"
        report += f"* A02:2021 - 암호화 실패 (Cryptographic Failures): {len(owasp_categories['A02:2021-Cryptographic Failures'])}개\n"
        report += f"* A03:2021 - 인젝션 (Injection): {len(owasp_categories['A03:2021-Injection'])}개\n"
        report += f"* A04:2021 - 안전하지 않은 설계 (Insecure Design): {len(owasp_categories['A04:2021-Insecure Design'])}개\n"
        report += f"* A05:2021 - 보안 설정 오류 (Security Misconfiguration): {len(owasp_categories['A05:2021-Security Misconfiguration'])}개\n"
        report += f"* A06:2021 - 취약하고 오래된 구성요소 (Vulnerable Components): {len(owasp_categories['A06:2021-Vulnerable and Outdated Components'])}개\n"
        report += f"* A07:2021 - 식별 및 인증 실패 (Auth Failures): {len(owasp_categories['A07:2021-Identification and Authentication Failures'])}개\n"
        report += f"* A08:2021 - 소프트웨어 및 데이터 무결성 실패 (Integrity Failures): {len(owasp_categories['A08:2021-Software and Data Integrity Failures'])}개\n"
        report += f"* A09:2021 - 보안 로깅 및 모니터링 실패 (Logging Failures): {len(owasp_categories['A09:2021-Security Logging and Monitoring Failures'])}개\n"
        report += f"* A10:2021 - 서버 사이드 요청 위조 (SSRF): {len(owasp_categories['A10:2021-Server-Side Request Forgery (SSRF)'])}개\n"
        
        report += "\n"
        
        report += f"**위험성 평가**: {risk_description}\n\n"
        report += f"**비즈니스 영향도**: {business_impact}\n\n"
        
        # 📊 **APT 공격 연계 위험도 (발견된 취약점 기반 동적 분석)**
        report += "**📊 APT 공격 연계 위험도**: "
        
        # 발견된 취약점별 APT 공격 가능성 분석
        apt_attack_score = 0
        apt_attack_vectors = []
        
        for vuln in vuln_list:
            vuln_type = vuln.get('type', '').lower()
            severity = vuln.get('severity', '').lower()
            module = vuln.get('module', '')
            
            # APT 공격 벡터별 점수 계산
            if 'sql injection' in vuln_type or '인젝션' in vuln_type:
                apt_attack_score += 15  # 데이터베이스 직접 접근
                apt_attack_vectors.append(f"SQL 인젝션({module})")
            elif '파일 업로드' in vuln_type or 'upload' in vuln_type:
                apt_attack_score += 12  # 웹쉘 설치 가능
                apt_attack_vectors.append(f"파일 업로드({module})")
            elif '인증' in vuln_type or '로그인' in vuln_type or 'authentication' in vuln_type:
                apt_attack_score += 10  # 권한 획득
                apt_attack_vectors.append(f"인증 우회({module})")
            elif 'xss' in vuln_type or '크로스사이트' in vuln_type:
                apt_attack_score += 8   # 세션 탈취
                apt_attack_vectors.append(f"XSS({module})")
            elif '경로 순회' in vuln_type or 'path traversal' in vuln_type:
                apt_attack_score += 7   # 시스템 파일 접근
                apt_attack_vectors.append(f"경로 순회({module})")
            elif '정보 노출' in vuln_type or 'information disclosure' in vuln_type:
                apt_attack_score += 6   # 정보 수집
                apt_attack_vectors.append(f"정보 노출({module})")
            elif 'csrf' in vuln_type or '사이트 간' in vuln_type:
                apt_attack_score += 5   # 무단 작업 실행
                apt_attack_vectors.append(f"CSRF({module})")
            elif '설정' in vuln_type or 'configuration' in vuln_type:
                apt_attack_score += 4   # 보안 설정 우회
                apt_attack_vectors.append(f"설정 오류({module})")
            else:
                apt_attack_score += 3   # 일반적 취약점
                apt_attack_vectors.append(f"{vuln.get('type', '알 수 없는 취약점')}({module})")
        
        # APT 공격 위험도 등급 결정
        if apt_attack_score >= 30:
            report += f"**💀 극도로 높음 ({apt_attack_score}점)** - 발견된 취약점들로 완전한 시스템 장악 및 단계별 침투 가능\n"
            report += f"**🔍 주요 공격 벡터**: {', '.join(apt_attack_vectors[:3])}\n"
        elif apt_attack_score >= 20:
            report += f"**🚨 매우 높음 ({apt_attack_score}점)** - 핵심 시스템 침투 및 데이터 유출 위험\n"
            report += f"**🔍 주요 공격 벡터**: {', '.join(apt_attack_vectors[:3])}\n"
        elif apt_attack_score >= 10:
            report += f"**⚠️ 높음 ({apt_attack_score}점)** - 다중 취약점으로 인한 복합적 공격 시나리오 구성 가능\n"
            report += f"**🔍 주요 공격 벡터**: {', '.join(apt_attack_vectors[:2])}\n"
        else:
            report += f"**🟡 중간 ({apt_attack_score}점)** - 제한적이지만 연계 공격 가능성 존재\n"
            report += f"**🔍 발견된 취약점**: {', '.join(apt_attack_vectors)}\n"
        
        report += "\n---\n\n"
        
        # 2. APT 공격 단계별 시나리오 (발견된 취약점 기반)
        report += "### 2️⃣ APT 공격 단계별 시나리오 (발견된 취약점 활용)\n\n"
        report += "> 💡 **현재 발견된 웹 취약점들을 활용한 APT(Advanced Persistent Threat) 공격 시나리오입니다.**\n\n"
        
        report += "**📋 발견된 취약점 기반 공격 시나리오**\n\n"
        
        # 발견된 취약점들을 단계별로 분류
        recon_vulns = []      # 정찰용 취약점
        access_vulns = []     # 초기 침투용 취약점
        escalation_vulns = [] # 권한 확장용 취약점
        movement_vulns = []   # 내부 이동용 취약점
        exfil_vulns = []      # 데이터 유출용 취약점
        persistence_vulns = [] # 지속성 확보용 취약점
        
        for vuln in vuln_list:
            vuln_type = vuln.get('type', '').lower()
            module = vuln.get('module', '')
            
            # 취약점 유형별 단계 분류
            if '정보 노출' in vuln_type or 'information disclosure' in vuln_type:
                recon_vulns.append(f"{vuln_type}({module})")
            elif 'sql injection' in vuln_type or '인젝션' in vuln_type:
                access_vulns.append(f"{vuln_type}({module})")
            elif '파일 업로드' in vuln_type or 'upload' in vuln_type:
                escalation_vulns.append(f"{vuln_type}({module})")
            elif 'xss' in vuln_type or '크로스사이트' in vuln_type:
                movement_vulns.append(f"{vuln_type}({module})")
            elif '경로 순회' in vuln_type or 'path traversal' in vuln_type:
                exfil_vulns.append(f"{vuln_type}({module})")
            elif '인증' in vuln_type or '로그인' in vuln_type or 'authentication' in vuln_type:
                persistence_vulns.append(f"{vuln_type}({module})")
            elif 'csrf' in vuln_type or '사이트 간' in vuln_type:
                exfil_vulns.append(f"{vuln_type}({module})")
            elif '설정' in vuln_type or 'configuration' in vuln_type:
                persistence_vulns.append(f"{vuln_type}({module})")
            else:
                # 일반적 취약점은 적절한 단계에 배치
                if not access_vulns:
                    access_vulns.append(f"{vuln_type}({module})")
                elif not escalation_vulns:
                    escalation_vulns.append(f"{vuln_type}({module})")
                else:
                    movement_vulns.append(f"{vuln_type}({module})")
        
        # 1단계: 정찰 및 정보 수집
        report += "**1단계: 정찰 및 정보 수집 (Reconnaissance & Intelligence Gathering)**\n"
        if recon_vulns:
            report += f"공격자는 {', '.join(recon_vulns)} 취약점을 통해 서버 구조, 데이터베이스 스키마, API 엔드포인트, 내부 네트워크 토폴로지 등 핵심 정보를 수집합니다. "
        else:
            report += "공격자는 웹 애플리케이션의 일반적인 정보 노출 취약점을 통해 서버 구조, 데이터베이스 스키마, API 엔드포인트, 내부 네트워크 토폴로지 등 핵심 정보를 수집합니다. "
        report += "에러 메시지와 디버그 정보를 통해 기술 스택, 버전 정보, 내부 경로 등을 파악하여 공격 벡터를 선정합니다.\n\n"
        
        # 2단계: 초기 침투
        report += "**2단계: 초기 침투 (Initial Access)**\n"
        if access_vulns:
            report += f"수집된 정보를 바탕으로 {', '.join(access_vulns)} 취약점을 악용하여 관리자 계정에 무단 접근합니다. "
        else:
            report += "수집된 정보를 바탕으로 SQL Injection 취약점을 악용하여 관리자 계정에 무단 접근합니다. "
        report += "인증 우회, 세션 하이재킹, 권한 상승 등을 통해 내부 시스템에 첫 발을 내딛습니다.\n\n"
        
        # 3단계: 권한 확장
        report += "**3단계: 권한 확장 (Privilege Escalation)**\n"
        if escalation_vulns:
            report += f"획득한 권한을 활용해 {', '.join(escalation_vulns)} 취약점을 통해 웹 셸(WebShell)을 서버에 업로드합니다. "
        else:
            report += "획득한 권한을 활용해 파일 업로드 취약점을 통해 웹 셸(WebShell)을 서버에 업로드합니다. "
        report += "파일 업로드 검증 우회, 경로 순회 취약점을 악용하여 원격 코드 실행(RCE) 권한을 확보하고, 내부 네트워크로의 이동 통로를 구축합니다.\n\n"
        
        # 4단계: 내부 정찰 및 이동
        report += "**4단계: 내부 정찰 및 이동 (Internal Reconnaissance & Lateral Movement)**\n"
        if movement_vulns:
            report += f"내부 네트워크에서 {', '.join(movement_vulns)} 취약점을 활용하여 관리자 세션을 탈취하고, 내부 시스템 간 자유로운 이동을 수행합니다. "
        else:
            report += "내부 네트워크에서 XSS 취약점을 활용하여 관리자 세션을 탈취하고, 내부 시스템 간 자유로운 이동을 수행합니다. "
        report += "세션 쿠키 탈취, 내부 로그 분석, 데이터베이스 접근 권한 획득을 통해 핵심 자산에 접근합니다.\n\n"
        
        # 5단계: 데이터 수집 및 유출
        report += "**5단계: 데이터 수집 및 유출 (Data Collection & Exfiltration)**\n"
        if exfil_vulns:
            report += f"핵심 데이터베이스에 접근하여 {', '.join(exfil_vulns)} 취약점을 통해 고객 정보, 금융 데이터, 지적재산권, 비즈니스 기밀 등을 대량으로 수집합니다. "
        else:
            report += "핵심 데이터베이스에 접근하여 고객 정보, 금융 데이터, 지적재산권, 비즈니스 기밀 등을 대량으로 수집합니다. "
        report += "데이터를 암호화하여 C&C(Command & Control) 서버로 유출하고, 증거 인멸을 위한 로그 삭제 작업을 수행합니다.\n\n"
        
        # 6단계: 지속성 확보 및 피해 확산
        report += "**6단계: 지속성 확보 및 피해 확산 (Persistence & Impact)**\n"
        if persistence_vulns:
            report += f"백도어와 루트킷을 설치하여 {', '.join(persistence_vulns)} 취약점을 통해 지속적인 접근을 확보하고, 랜섬웨어를 배포하여 시스템을 완전히 마비시킵니다. "
        else:
            report += "백도어와 루트킷을 설치하여 지속적인 접근을 확보하고, 랜섬웨어를 배포하여 시스템을 완전히 마비시킵니다. "
        report += "이를 통해 조직의 운영 중단, 평판 손상, 법적 책임, 고객 신뢰도 하락 등 다차원적 피해를 야기합니다.\n\n"
        
        report += "\n---\n\n"
        
        # 3. 발견된 취약점들이 복합적으로 사용된 실제 해킹 사례
        report += "### 3️⃣ 발견된 취약점들이 복합적으로 사용된 실제 해킹 사례\n\n"
        
        # 발견된 취약점 유형들을 수집
        found_vuln_types = []
        for vuln in vuln_list:
            vuln_type = vuln.get('type', '')
            if vuln_type and vuln_type not in found_vuln_types:
                found_vuln_types.append(vuln_type)
        
        if found_vuln_types:
            report += f"**🔍 발견된 취약점 유형**: {', '.join(found_vuln_types)}\n\n"
            report += "**💡 복합적 공격 시나리오**: 위의 취약점들이 연계되어 사용될 경우 다음과 같은 실제 해킹 사례와 유사한 공격이 가능합니다.\n\n"
        
        # 이미지에서 읽어온 incidents 데이터 활용
        all_incidents = []
        for vuln in vuln_list:
            incidents = vuln.get('incidents', [])
            if incidents:
                all_incidents.extend(incidents)
        
        if all_incidents:
            # 중복 제거 및 정렬
            unique_incidents = []
            seen_names = set()
            for incident in all_incidents:
                name = incident.get('name', '')
                if name and name not in seen_names:
                    unique_incidents.append(incident)
                    seen_names.add(name)
            
            # 최대 3개까지만 표시
            for i, incident in enumerate(unique_incidents[:3], 1):
                name = incident.get('name', f'복합 공격 사례 {i}')
                date = incident.get('date', '날짜 미상')
                summary = incident.get('summary', '사고 요약 정보가 없습니다.')
                source = incident.get('source', '출처: 보안진단팀 분석')
                
                report += f"**🔸 {name} ({date})**\n"
                report += f"{summary}\n"
                report += f"*{source}*\n\n"
        else:
            report += "이미지에서 읽어온 구체적인 복합 공격 사례 정보가 없습니다. 추가 진단을 통해 관련 사례를 제공하겠습니다.\n\n"
        
        report += "\n---\n\n"
        
        # 4. 대응 전략
        report += "### 4️⃣ 대응 전략\n\n"
        
        # 권장 대응 시한
        report += "**⏰ 권장 대응 시한**: "
        if high_severity_count >= 3 or (len(upload_vulns) > 0 and len(auth_vulns) > 0):
            report += "**즉시 (24시간 이내)**\n"
        elif high_severity_count >= 1 or len(upload_vulns) > 0:
            report += "**긴급 (72시간 이내)**\n"
        elif total_vulns >= 3:
            report += "**신속 (1주일 이내)**\n"
        else:
            report += "**일반 (2주일 이내)**\n"
        
        report += "\n**즉시 대응 (0–7일)**\n\n"
        
        # 실제 취약점에 따른 즉시 대응 방안
        if auth_vulns:
            report += f"* {', '.join(auth_vulns)} 관련 엔드포인트 외부 접근 차단\n"
        if upload_vulns:
            report += f"* {', '.join(upload_vulns)} 기능 임시 비활성화 및 파일 업로드 제한\n"
        if xss_vulns:
            report += f"* {', '.join(xss_vulns)} 방지를 위한 WAF 규칙 즉시 적용\n"
        if info_vulns:
            report += f"* {', '.join(info_vulns)} 관련 디버그 모드 및 로그 노출 차단\n"
        
        report += "* 24시간 내 긴급 패치 완료 및 모의 해킹 재검증\n\n"
        
        report += "**단기 강화 (1–3주)**\n\n"
        
        # 취약점 유형에 따른 단기 강화 방안
        if auth_vulns:
            report += "* 인증·권한 관리 시스템 전면 점검 및 강화\n"
        if upload_vulns:
            report += "* 파일 업로드 검증 로직 재설계 및 화이트리스트 적용\n"
        if xss_vulns:
            report += "* 입력값 검증 및 출력 인코딩 표준화\n"
        if info_vulns:
            report += "* 정보 노출 방지를 위한 에러 처리 및 로깅 정책 수립\n"
        
        report += "* 전 직원 대상 보안 인식 교육 및 모의 해킹 워크숍\n\n"
        
        report += "**중장기 체계화 (1–3개월+)**\n\n"
        
        # 취약점 심각도에 따른 중장기 계획
        if high_severity_count > 0:
            report += "* 고위험 취약점 재발 방지를 위한 보안 개발 생명주기(SDLC) 도입\n"
        if medium_severity_count > 0:
            report += "* 중간 위험 취약점 모니터링을 위한 보안 KPI 설정\n"
        
        report += "* 분기별 CISO 검토 회의 제도화 및 SOC·SIEM 고도화\n"
        report += "* 외부 보안 인증(ISMS-P 등) 준비 및 보안 성숙도 평가\n\n"
    else:
        report += "진단된 취약점 정보가 부족하여 구체적인 공격 시나리오를 제시하기 어렵습니다. 추가 진단을 통해 취약점을 정확히 파악한 후 상세한 공격 시나리오를 제공하겠습니다.\n\n"
    
    report += "---\n\n## 5. 메타인지 교육 제안 (Metacognition Training)\n\n"
    report += "> **목표**: 전직원 대상 메타인지 역량 강화로 자발적 위험 탐지·보고 문화 조성\n\n"
    
    # 5. 메타인지 교육 제안
    report += "1. **교육 목표**: '내가 보는 정보의 안전성'을 스스로 점검하고 이상 징후를 조기에 식별\n"
    report += "2. **커리큘럼**:\n\n"
    report += "   * **위협 모델링 워크숍**: 실제 취약점 사례 분석 및 리스크 매핑\n"
    
    # 실제 취약점에 따른 모의해킹 실습
    if xss_vulns:
        report += f"   * **모의해킹 실습**: {', '.join(xss_vulns)} 시나리오 구성 및 대응 경험\n"
    if upload_vulns:
        report += f"   * **파일 업로드 보안 실습**: {', '.join(upload_vulns)} 취약점 탐지 및 방어 방법\n"
    if auth_vulns:
        report += f"   * **인증 보안 실습**: {', '.join(auth_vulns)} 취약점 탐지 및 대응 방법\n"
    if info_vulns:
        report += f"   * **정보 보호 실습**: {', '.join(info_vulns)} 취약점 탐지 및 방어 방법\n"
    
    report += "   * **인지 회고 세션**: 탐지 과정 기록 후 팀별 공유·피드백\n"
    report += "   * **퀴즈 기반 점검**: 비정형 취약점 탐지 능력 검증\n"
    report += "   * **행동 체크리스트**: 배포 전 필수 보안 점검 리스트 실습\n"
    report += "3. **기대 효과**:\n\n"
    
    # 취약점 수에 따른 기대 효과
    total_vulns = len(vuln_list)
    if total_vulns > 0:
        report += f"   * {total_vulns}개 취약점 유형별 탐지 능력 향상\n"
        report += "   * 자발적 보안 리포트 제출 건수 증가\n"
        report += "   * 사고 대응 시간 개선\n\n"
    else:
        report += "   * 취약점 탐지 능력 향상\n"
        report += "   * 자발적 보안 리포트 제출 건수 증가\n"
        report += "   * 사고 대응 시간 개선\n\n"
    
    report += "---\n\n## 6. 종합 대응 로드맵 (Comprehensive Response Roadmap)\n\n"
    
    # 6. 종합 대응 로드맵 - 실제 취약점 기반 동적 생성
    report += "| 단계         | 기간     | 주요 활동                                                                     | 담당 조직/팀     |\n"
    report += "| ---------- | ------ | ------------------------------------------------------------------------- | ----------- |\n"
    
    # 긴급 대응 단계
    urgent_activities = []
    if auth_vulns:
        urgent_activities.append(f"{', '.join(auth_vulns)} 관련 엔드포인트 차단")
    if upload_vulns:
        urgent_activities.append(f"{', '.join(upload_vulns)} 기능 임시 비활성화")
    if xss_vulns:
        urgent_activities.append(f"{', '.join(xss_vulns)} 방지 WAF 규칙 적용")
    if info_vulns:
        urgent_activities.append(f"{', '.join(info_vulns)} 관련 디버그 모드 차단")
    
    urgent_activities.append("긴급 모의해킹 실시")
    urgent_activities_str = "<br>- ".join(urgent_activities)
    
    report += f"| **긴급 대응**  | 0–7일   | - {urgent_activities_str}                  | 보안팀·개발팀·SOC |\n"
    
    # 단기 강화 단계
    short_activities = []
    if auth_vulns:
        short_activities.append("인증·권한 관리 시스템 전면 점검")
    if upload_vulns:
        short_activities.append("파일 업로드 검증 로직 재설계")
    if xss_vulns:
        short_activities.append("입력값 검증 및 출력 인코딩 표준화")
    if info_vulns:
        short_activities.append("에러 처리 및 로깅 정책 수립")
    
    short_activities.append("전 직원 보안 인식 교육·워크숍 실시")
    short_activities_str = "<br>- ".join(short_activities)
    
    report += f"| **단기 강화**  | 1–3주   | - {short_activities_str}                             | 개발팀·교육팀     |\n"
    
    # 중기 체계화 단계
    medium_activities = []
    if high_severity_count > 0:
        medium_activities.append("고위험 취약점 재발 방지를 위한 SDLC 도입")
    if medium_severity_count > 0:
        medium_activities.append("중간 위험 취약점 모니터링을 위한 KPI 설정")
    
    medium_activities.extend([
        "분기별 CISO 검토 회의 제도화",
        "SOC·SIEM 고도화"
    ])
    medium_activities_str = "<br>- ".join(medium_activities)
    
    report += f"| **중기 체계화** | 1–3개월  | - {medium_activities_str}            | 전략팀·거버넌스팀   |\n"
    
    # 장기 개선 단계
    long_activities = []
    if total_vulns > 5:
        long_activities.append("Red Team·Blue Team 훈련")
    if any('llm' in v.lower() or 'ai' in v.lower() for v in vuln_types):
        long_activities.append("온프레미스 LLM 보안 검토")
    
    long_activities.extend([
        "외부 보안 인증 준비",
        "보안 성숙도 평가"
    ])
    long_activities_str = "<br>- ".join(long_activities)
    
    report += f"| **장기 개선**  | 3–6개월+ | - {long_activities_str} | 보안전략팀·감사팀   |\n\n"
    
    report += "---\n\n*End of Report*"
    
    return report

def generate_executive_summary(vuln_list: List[Dict]) -> str:
    """
    경영진을 위한 실행 요약을 생성합니다.
    
    Args:
        vuln_list: 취약점 분석 결과 JSON 배열
    
    Returns:
        str: 실행 요약 Markdown
    """
    
    if not vuln_list:
        return "# 실행 요약\n\n분석된 취약점이 없습니다."
    
    high_severity = [v for v in vuln_list if v.get('severity') == '높음']
    medium_severity = [v for v in vuln_list if v.get('severity') == '중간']
    low_severity = [v for v in vuln_list if v.get('severity') == '낮음']
    
    summary = f"""# 📊 실행 요약

## 취약점 현황

* **총 취약점 수**: {len(vuln_list)}개
* **높은 심각도**: {len(high_severity)}개
* **중간 심각도**: {len(medium_severity)}개  
* **낮은 심각도**: {len(low_severity)}개

## 주요 취약점 유형

"""
    
    vuln_types = {}
    for vuln in vuln_list:
        vuln_type = vuln.get('type', 'Unknown')
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    for vuln_type, count in vuln_types.items():
        summary += f"* **{vuln_type}**: {count}개\n"
    
    summary += "\n## 긴급 조치 필요 사항\n\n"
    
    if high_severity:
        summary += "### 🔴 높은 심각도 취약점\n\n"
        for vuln in high_severity:
            summary += f"* **{vuln.get('id')}** - {vuln.get('type')}: {vuln.get('summary')}\n"
        summary += "\n"
    
    summary += "## 권고사항\n\n"
    summary += "1. **즉시 조치**: 높은 심각도 취약점 우선 패치\n"
    summary += "2. **단기 조치**: 보안 모니터링 강화 및 접근 제어\n"
    summary += "3. **중장기 조치**: 보안 아키텍처 재설계 및 교육 프로그램 운영\n\n"
    
    summary += f"---\n\n*생성일: {datetime.now().strftime('%Y년 %m월 %d일 %H:%M')}*"
    
    return summary 