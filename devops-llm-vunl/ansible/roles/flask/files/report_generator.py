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
* **보고 목적**: 진단된 취약점을 통해 조직원의 보안정책 준수 의지를 강화하고, 보호동기 이론(PMT) 기반 실행 전략을 제시

---

## 2. 취약점 요약 Table

| 취약점 ID   | 유형                | 심각도 | 발견 모듈/URL                        | 요약 설명                                |
| -------- | ----------------- | --- | -------------------------------- | ------------------------------------ |
"""
    
    # 2. 취약점 요약 테이블 - 실제 이미지 데이터 사용
    for i, vuln in enumerate(vuln_list, 1):
        # 이미지에서 읽어온 실제 데이터 사용
        vuln_id = vuln.get('id', f'VULN-{i:03d}')
        vuln_type = vuln.get('type', '알 수 없는 취약점')
        severity = vuln.get('severity', '중간')
        module = vuln.get('module', '알 수 없는 모듈')
        summary = vuln.get('summary', '취약점 요약 정보가 없습니다.')
        
        report += f"| {vuln_id} | {vuln_type} | {severity} | {module} | {summary} |\n"
    
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
    
    # 4. 경영진 보고사항
    high_severity = [v for v in vuln_list if v.get('severity') == '높음']
    medium_severity = [v for v in vuln_list if v.get('severity') == '중간']
    
    report += "**취약점 심각도 요약**\n\n"
    report += "* '높음': "
    high_types = [v.get('type') for v in high_severity]
    report += ", ".join(high_types) if high_types else "없음"
    report += " → 즉시 패치\n"
    
    report += "* '중간': "
    medium_types = [v.get('type') for v in medium_severity]
    report += ", ".join(medium_types) if medium_types else "없음"
    report += " → 단기 보강\n\n"
    
    report += "**APT 공격 시나리오**\n"
    
    # 실제 진단된 취약점을 기반으로 APT 시나리오 생성
    vuln_types = [v.get('type', '') for v in vuln_list if v.get('type')]
    
    if vuln_types:
        report += f"공격자는 진단된 취약점들을 종합적으로 활용하여 체계적인 공격을 수행할 수 있습니다. "
        
        # 인증 관련 취약점이 있는 경우
        auth_vulns = [v for v in vuln_types if any(keyword in v.lower() for keyword in ['인증', '로그인', '세션', '권한'])]
        if auth_vulns:
            report += f"먼저 {', '.join(auth_vulns)} 취약점을 이용해 관리자 권한을 획득합니다. "
        
        # 파일 업로드 관련 취약점이 있는 경우
        upload_vulns = [v for v in vuln_types if any(keyword in v.lower() for keyword in ['업로드', '파일', '업로드'])]
        if upload_vulns:
            report += f"이후 {', '.join(upload_vulns)} 취약점을 통해 웹 셸을 서버에 업로드하여 원격 코드 실행 권한을 확보합니다. "
        
        # XSS 관련 취약점이 있는 경우
        xss_vulns = [v for v in vuln_types if any(keyword in v.lower() for keyword in ['xss', '스크립트', '크로스사이트'])]
        if xss_vulns:
            report += f"이 권한을 활용해 {', '.join(xss_vulns)} 취약점을 연계하여 세션 쿠키와 내부 로그를 탈취·분석합니다. "
        
        # 정보 누출 관련 취약점이 있는 경우
        info_vulns = [v for v in vuln_types if any(keyword in v.lower() for keyword in ['정보', '누출', '노출', '디버그'])]
        if info_vulns:
            report += f"네트워크에 진입한 공격자는 {', '.join(info_vulns)} 취약점을 남용해 서비스 설정을 완전히 변경하고 백업 데이터를 삭제·암호화합니다. "
        
        # 기타 취약점들
        other_vulns = [v for v in vuln_types if v not in auth_vulns + upload_vulns + xss_vulns + info_vulns]
        if other_vulns:
            report += f"마지막으로 {', '.join(other_vulns)} 취약점을 통해 랜섬웨어를 배포하거나 대량의 고객 데이터를 유출하여 서비스 마비와 평판 손상을 동시에 일으킵니다.\n\n"
        else:
            report += "이러한 취약점들을 통해 랜섬웨어를 배포하거나 대량의 고객 데이터를 유출하여 서비스 마비와 평판 손상을 동시에 일으킵니다.\n\n"
    else:
        report += "진단된 취약점 정보가 부족하여 구체적인 공격 시나리오를 제시하기 어렵습니다. 추가 진단을 통해 취약점을 정확히 파악한 후 상세한 공격 시나리오를 제공하겠습니다.\n\n"
    
    report += "**즉시 대응 (0–7일)**\n\n"
    
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
    if high_severity:
        report += "* 고위험 취약점 재발 방지를 위한 보안 개발 생명주기(SDLC) 도입\n"
    if medium_severity:
        report += "* 중간 위험 취약점 모니터링을 위한 보안 KPI 설정\n"
    
    report += "* 분기별 CISO 검토 회의 제도화 및 SOC·SIEM 고도화\n"
    report += "* 외부 보안 인증(ISMS-P 등) 준비 및 보안 성숙도 평가\n\n"
    
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
    if high_severity:
        medium_activities.append("고위험 취약점 재발 방지를 위한 SDLC 도입")
    if medium_severity:
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