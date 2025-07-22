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

![취약점 진단 결과]({image_filename})

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
        
        # OWASP Top 10 취약점 기준으로 위험성 등급 평가
        owasp_vulns = []
        for vuln in vuln_list:
            vuln_type = vuln.get('type', '').lower()
            # OWASP Top 10에 속하는 취약점들 판단
            if any(keyword in vuln_type for keyword in [
                'sql injection', '인젝션', 'xss', 'csrf', '경로 순회', 'path traversal',
                '파일 업로드', 'file upload', '인증', 'authentication', '세션', 'session',
                '정보 노출', 'information disclosure', '설정', 'configuration'
            ]):
                owasp_vulns.append(vuln.get('type', ''))
        
        owasp_vuln_count = len(owasp_vulns)
        
        # 위험성 등급 결정 (OWASP Top 10 기준)
        if owasp_vuln_count >= 3:
            risk_level = "🔴 **극도로 위험 (Critical Risk)**"
        elif owasp_vuln_count >= 1:
            risk_level = "🟠 **매우 위험 (High Risk)**"
        elif total_vulns >= 2:
            risk_level = "🟡 **위험 (Medium Risk)**"
        else:
            risk_level = "🟢 **낮은 위험 (Low Risk)**"
        
        # 진단된 취약점을 동적으로 분석한 해킹 위험성 평가
        risk_description = f"총 {total_vulns}개의 취약점이 발견되어 복합적 해킹 공격 위험이 존재합니다. "
        
        # 이미지에서 읽어온 위험성 정보 우선 활용
        risk_assessments = []
        for vuln in vuln_list:
            risk = vuln.get('risk', '')
            if risk and risk != '위험성 정보가 없습니다.':
                risk_assessments.append(risk)
        
        if risk_assessments:
            # 이미지에서 읽어온 위험성 정보를 기반으로 동적 분석
            risk_description += f"발견된 취약점들의 위험성: {risk_assessments[0]} "
        
        # OWASP Top 10 기준 동적 위험성 분석
        if owasp_vuln_count > 0:
            risk_description += f"OWASP Top 10 취약점 {owasp_vuln_count}개({', '.join(owasp_vulns)})가 발견되어 즉시적인 보안 대응이 필요합니다. "
        
        if total_vulns >= 3:
            risk_description += f"다중 취약점({total_vulns}개)으로 인한 연계 공격 시나리오가 구성 가능합니다. "
        
        # 실제 발견된 취약점 유형별 동적 분석
        found_vuln_types = []
        for vuln in vuln_list:
            vuln_type = vuln.get('type', '')
            if vuln_type and vuln_type not in found_vuln_types:
                found_vuln_types.append(vuln_type)
        
        if found_vuln_types:
            risk_description += f"발견된 주요 취약점 유형: {', '.join(found_vuln_types)}. "
        
        # 취약점 조합 가능성 분석 (동적)
        if len(found_vuln_types) >= 2:
            risk_description += f"이러한 취약점들이 연계되어 사용될 경우 더욱 심각한 보안 위협이 될 수 있습니다."
        
        # 위험성 등급에 따른 비즈니스 영향도
        if owasp_vuln_count >= 3:
            business_impact = "조직의 핵심 비즈니스에 치명적인 위협이 될 수 있으며, 시스템 완전 장악 및 대규모 데이터 유출 위험이 있습니다."
        elif owasp_vuln_count >= 1:
            business_impact = "조직의 안정성에 심각한 영향을 줄 수 있으며, 핵심 데이터 유출 및 서비스 중단 위험이 있습니다."
        elif total_vulns >= 2:
            business_impact = "조직의 안정성에 영향을 줄 수 있는 위험이 있으며, 제한적 데이터 유출 가능성이 있습니다."
        else:
            business_impact = "조직의 안정성에 미미한 영향을 줄 수 있으며, 즉시적인 위협은 낮습니다."
        
        report += f"**위험성 등급**: {risk_level}\n\n"
        report += f"**위험성 등급 분류 범례 (OWASP Top 10 기준)**:\n"
        report += f"* 🔴 **극도로 위험 (Critical Risk)**: OWASP Top 10 취약점 3개 이상\n"
        report += f"* 🟠 **매우 위험 (High Risk)**: OWASP Top 10 취약점 1개 이상\n"
        report += f"* 🟡 **위험 (Medium Risk)**: 총 취약점 2개 이상\n"
        report += f"* 🟢 **낮은 위험 (Low Risk)**: 총 취약점 1개 이하\n\n"
        
        report += f"**현재 위험성 등급 판단 근거**:\n"
        if owasp_vuln_count >= 3:
            report += f"* 극도로 위험: OWASP Top 10 취약점 {owasp_vuln_count}개 발견\n"
        elif owasp_vuln_count >= 1:
            report += f"* 매우 위험: OWASP Top 10 취약점 {owasp_vuln_count}개 발견\n"
        elif total_vulns >= 2:
            report += f"* 위험: 총 취약점 {total_vulns}개 발견\n"
        else:
            report += f"* 낮은 위험: 총 취약점 {total_vulns}개 발견\n"
        
        report += f"\n**위험성 등급 판단 기준 상세 설명**:\n"
        report += f"* **OWASP Top 10 취약점**: 웹 애플리케이션에서 가장 위험한 10가지 취약점 유형\n"
        report += f"* **3개 이상**: 다중 취약점으로 인한 복합적 공격 위험\n"
        report += f"* **1개 이상**: 단일 취약점으로도 심각한 보안 위협\n"
        report += f"* **총 취약점 수**: 전체 발견된 취약점의 수량 기준\n"
        report += "\n"
        report += f"**진단 결과 요약**:\n"
        report += f"* 총 발견 취약점: {total_vulns}개\n"
        
        # 심각도별 요약 (0개인 경우 제외)
        if high_severity_count > 0:
            report += f"* 높은 심각도: {high_severity_count}개\n"
        if medium_severity_count > 0:
            report += f"* 중간 심각도: {medium_severity_count}개\n"
        
        # OWASP Top 10 웹 취약점 유형별 요약 (모두 표기, 발견된 것만 카운트)
        report += f"**OWASP Top 10 웹 취약점**:\n"
        report += f"* A01: 인증 우회 (OWASP A07): {len(auth_vulns)}개\n"
        report += f"* A02: 보안 설정 오류 (OWASP A05): {len([v for v in vuln_types if '설정' in v.lower() or 'config' in v.lower() or '보안' in v.lower()])}개\n"
        report += f"* A03: XSS 취약점 (OWASP A03, CWE-79): {len(xss_vulns)}개\n"
        report += f"* A04: 정보 노출 (OWASP A05): {len(info_vulns)}개\n"
        report += f"* A05: SQL Injection (OWASP A03, CWE-89): {len([v for v in vuln_types if 'sql' in v.lower() or '인젝션' in v.lower()])}개\n"
        report += f"* A06: CSRF (OWASP A01, CWE-352): {len([v for v in vuln_types if 'csrf' in v.lower() or '위조' in v.lower()])}개\n"
        report += f"* A07: 경로 순회 (OWASP A01, CWE-22): {len([v for v in vuln_types if '경로' in v.lower() or '순회' in v.lower() or 'path' in v.lower()])}개\n"
        report += f"* A08: 세션 관리 (OWASP A02, CWE-384): {len([v for v in vuln_types if '세션' in v.lower() or 'session' in v.lower()])}개\n"
        report += f"* A09: 파일 업로드 (OWASP A05): {len(upload_vulns)}개\n"
        report += f"* A10: 취약한 구성요소 (OWASP A06): {len([v for v in vuln_types if '구성요소' in v.lower() or 'component' in v.lower() or '라이브러리' in v.lower()])}개\n"
        
        report += "\n"
        
        report += f"**위험성 평가**: {risk_description}\n\n"
        report += f"**비즈니스 영향도**: {business_impact}\n\n"
        
        # 위험성 등급에 따른 APT 공격 연계 위험도
        report += "**📊 APT 공격 연계 위험도**: "
        if owasp_vuln_count >= 3:
            report += "**극도로 높음** - OWASP Top 10 취약점 다수 존재로 완전한 시스템 장악 및 단계별 침투 가능\n"
        elif owasp_vuln_count >= 1:
            report += "**매우 높음** - OWASP Top 10 취약점 존재로 핵심 시스템 침투 및 데이터 유출 위험\n"
        elif total_vulns >= 2:
            report += "**높음** - 다중 취약점으로 인한 복합적 공격 시나리오 구성 가능\n"
        else:
            report += "**중간** - 제한적이지만 연계 공격 가능성 존재\n"
        
        report += "\n---\n\n"
        
        # 2. APT 공격 단계별 시나리오 예시
        report += "### 2️⃣ APT 공격 단계별 시나리오 예시\n\n"
        report += "> 💡 **현재 발견된 웹 취약점들을 활용한 APT(Advanced Persistent Threat) 공격 시나리오 예시입니다.**\n\n"
        
        report += "**📋 공격 단계별 시나리오 예시**\n\n"
        
        # 1단계: 정찰 및 정보 수집 예시
        report += "**1단계: 정찰 및 정보 수집 (Reconnaissance & Intelligence Gathering)**\n"
        report += "공격자는 웹 애플리케이션의 정보 노출 취약점을 통해 서버 구조, 데이터베이스 스키마, API 엔드포인트, 내부 네트워크 토폴로지 등 핵심 정보를 수집합니다. "
        report += "에러 메시지와 디버그 정보를 통해 기술 스택, 버전 정보, 내부 경로 등을 파악하여 공격 벡터를 선정합니다.\n\n"
        
        # 2단계: 초기 침투 예시
        report += "**2단계: 초기 침투 (Initial Access)**\n"
        report += "수집된 정보를 바탕으로 SQL Injection 취약점을 악용하여 관리자 계정에 무단 접근합니다. "
        report += "SQL 인젝션을 통한 인증 우회, 세션 하이재킹, 권한 상승 등을 통해 내부 시스템에 첫 발을 내딛습니다.\n\n"
        
        # 3단계: 권한 확장 예시
        report += "**3단계: 권한 확장 (Privilege Escalation)**\n"
        report += "획득한 권한을 활용해 파일 업로드 취약점을 통해 웹 셸(WebShell)을 서버에 업로드합니다. "
        report += "파일 업로드 검증 우회, 경로 순회 취약점을 악용하여 원격 코드 실행(RCE) 권한을 확보하고, 내부 네트워크로의 이동 통로를 구축합니다.\n\n"
        
        # 4단계: 내부 정찰 및 이동 예시
        report += "**4단계: 내부 정찰 및 이동 (Internal Reconnaissance & Lateral Movement)**\n"
        report += "내부 네트워크에서 XSS 취약점을 활용하여 관리자 세션을 탈취하고, 내부 시스템 간 자유로운 이동을 수행합니다. "
        report += "XSS를 통한 세션 쿠키 탈취, 내부 로그 분석, 데이터베이스 접근 권한 획득을 통해 핵심 자산에 접근합니다.\n\n"
        
        # 5단계: 데이터 수집 및 유출 예시
        report += "**5단계: 데이터 수집 및 유출 (Data Collection & Exfiltration)**\n"
        report += "핵심 데이터베이스에 접근하여 고객 정보, 금융 데이터, 지적재산권, 비즈니스 기밀 등을 대량으로 수집합니다. "
        report += "데이터를 암호화하여 C&C(Command & Control) 서버로 유출하고, 증거 인멸을 위한 로그 삭제 작업을 수행합니다.\n\n"
        
        # 6단계: 지속성 확보 및 피해 확산 예시
        report += "**6단계: 지속성 확보 및 피해 확산 (Persistence & Impact)**\n"
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