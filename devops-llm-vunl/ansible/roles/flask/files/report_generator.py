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
* **대상 시스템**: {target_system} 인증·업로드·관리 기능
* **보고 목적**: 진단된 취약점을 통해 조직원의 보안정책 준수 의지를 강화하고, 보호동기 이론(PMT) 기반 실행 전략을 제시

---

## 2. 취약점 요약 Table

| 취약점 ID   | 유형                | 심각도 | 발견 모듈/URL                        | 요약 설명                                |
| -------- | ----------------- | --- | -------------------------------- | ------------------------------------ |
"""
    
    # 2. 취약점 요약 테이블
    for vuln in vuln_list:
        report += f"| {vuln.get('id', 'N/A')} | {vuln.get('type', 'N/A')} | {vuln.get('severity', 'N/A')} | {vuln.get('module', 'N/A')} | {vuln.get('summary', 'N/A')} |\n"
    
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
    report += "공격자는 먼저 인증 우회 취약점을 이용해 관리자 권한을 획득합니다. 이후 파일 업로드 검증 미흡 취약점을 통해 웹 셸을 서버에 업로드하여 원격 코드 실행 권한을 확보합니다. 이 권한을 활용해 크로스사이트 스크립팅과 정보 누출 취약점을 연계, 세션 쿠키와 내부 로그를 탈취·분석하여 네트워크 내부로 수평 이동합니다. 네트워크에 진입한 공격자는 관리자 페이지 노출 취약점을 남용해 서비스 설정을 완전히 변경하고 백업 데이터를 삭제·암호화합니다. 마지막으로 악성 콘텐츠 삽입 취약점을 통해 랜섬웨어를 배포하거나 대량의 고객 데이터를 유출하여 서비스 마비와 평판 손상을 동시에 일으킵니다.\n\n"
    
    report += "**즉시 대응 (0–7일)**\n\n"
    report += "* 모든 취약점 엔드포인트 및 관리자 URL 외부 접근 차단\n"
    report += "* WAF 규칙으로 변수 조작·스크립트 삽입 요청 차단\n"
    report += "* 24시간 내 긴급 패치 완료 및 모의 해킹 재검증\n\n"
    
    report += "**단기 강화 (1–3주)**\n\n"
    report += "* 전사 코드 리뷰 및 자동화 스캔 도구 도입\n"
    report += "* 전 직원 대상 보안 인식 교육 및 모의 해킹 워크숍\n\n"
    
    report += "**중장기 체계화 (1–3개월+)**\n\n"
    report += "* 보안 KPI 설정 및 분기별 CISO 검토 회의 제도화\n"
    report += "* SOC·SIEM 고도화, 외부 보안 인증(ISMS-P 등) 준비\n\n"
    
    report += "---\n\n## 5. 메타인지 교육 제안 (Metacognition Training)\n\n"
    report += "> **목표**: 전직원 대상 메타인지 역량 강화로 자발적 위험 탐지·보고 문화 조성\n\n"
    
    # 5. 메타인지 교육 제안
    report += "1. **교육 목표**: '내가 보는 정보의 안전성'을 스스로 점검하고 이상 징후를 조기에 식별\n"
    report += "2. **커리큘럼**:\n\n"
    report += "   * **위협 모델링 워크숍**: 실제 취약점 사례 분석 및 리스크 매핑\n"
    report += "   * **모의해킹 실습**: XSS·RCE 시나리오 구성 및 대응 경험\n"
    report += "   * **인지 회고 세션**: 탐지 과정 기록 후 팀별 공유·피드백\n"
    report += "   * **퀴즈 기반 점검**: 비정형 취약점 탐지 능력 검증\n"
    report += "   * **행동 체크리스트**: 배포 전 필수 보안 점검 리스트 실습\n"
    report += "3. **기대 효과**:\n\n"
    report += "   * 취약점 탐지 속도 50% 단축\n"
    report += "   * 자발적 보안 리포트 제출 건수 2배 증가\n"
    report += "   * 사고 대응 시간 평균 40% 개선\n\n"
    
    report += "---\n\n## 6. 종합 대응 로드맵 (Comprehensive Response Roadmap)\n\n"
    
    # 6. 종합 대응 로드맵
    report += """| 단계         | 기간     | 주요 활동                                                                     | 담당 조직/팀     |
| ---------- | ------ | ------------------------------------------------------------------------- | ----------- |
| **긴급 대응**  | 0–7일   | - 취약점 패치 및 WAF 규칙 즉시 적용<br>- 위험 엔드포인트 차단<br>- 긴급 모의해킹 실시                  | 보안팀·개발팀·SOC |
| **단기 강화**  | 1–3주   | - 코드 리뷰 및 스캔 자동화 도입<br>- 전 직원 보안 인식 교육·워크숍 실시                             | 개발팀·교육팀     |
| **중기 체계화** | 1–3개월  | - 보안 거버넌스 강화(KPI 포함)<br>- 분기별 CISO 검토 회의 제도화<br>- SOC·SIEM 고도화            | 전략팀·거버넌스팀   |
| **장기 개선**  | 3–6개월+ | - Red Team·Blue Team 훈련<br>- 온프레미스 LLM 검토<br>- 외부 보안 인증 준비<br>- 보안 성숙도 평가 | 보안전략팀·감사팀   |

---

*End of Report*
"""
    
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