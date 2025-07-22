import json
from datetime import datetime
from typing import List, Dict, Optional

def generate_final_report(
    vuln_list: List[Dict], 
    target_system: str = "웹 애플리케이션",
    image_filename: str = "unknown.jpg",
    author: str = "자동 생성 시스템"
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
    
    today = datetime.now().strftime("%Y년 %m월 %d일")
    
    # 1. 보고서 개요
    report = f"""# ▶ 최종 보안 취약점 준수 강화 리포트

## 1. 보고서 개요

* **작성일**: {today}
* **작성자/팀**: {author}
* **대상 시스템**: {target_system}
* **보고 목적**: "진단된 취약점이 조직원의 보안정책 준수 의지에 미치는 영향을 최소화하고, 보호동기 강화 실행 전략 제시"

---

## 2. 취약점 요약 Table

| 취약점 ID | 유형 | 심각도 | 발견 모듈/URL | 요약 설명 |
|-----------|------|--------|---------------|-----------|
"""
    
    # 2. 취약점 요약 테이블
    for vuln in vuln_list:
        report += f"| {vuln.get('id', 'N/A')} | {vuln.get('type', 'N/A')} | {vuln.get('severity', 'N/A')} | {vuln.get('module', 'N/A')} | {vuln.get('summary', 'N/A')} |\n"
    
    report += "\n---\n\n## 3. 지각된 위험성 (Perceived Risk)\n\n"
    report += "> **목표**: 해당 취약점이 조직에 줄 수 있는 **구체적·치명적 피해**를 **5줄 이상** 상세히 기술\n\n"
    
    # 3. 지각된 위험성
    for vuln in vuln_list:
        report += f"### {vuln.get('id', 'N/A')} – {vuln.get('type', 'N/A')}\n\n"
        report += f"{vuln.get('risk', '위험성 정보가 없습니다.')}\n\n"
    
    report += "---\n\n## 4. 유사 해킹 사고 사례 (Incident Case Studies)\n\n"
    report += "> **목표**: **각 사례마다** 사례 개요·발생 경위·피해 규모를 **5줄 이상**으로 상세하게 설명\n\n"
    
    # 4. 유사 해킹 사고 사례
    for vuln in vuln_list:
        report += f"### {vuln.get('id', 'N/A')} – {vuln.get('type', 'N/A')}\n\n"
        
        incidents = vuln.get('incidents', [])
        if incidents:
            for incident in incidents:
                report += f"* **사례명**: {incident.get('name', 'N/A')}\n\n"
                report += f"  * 발생일: {incident.get('date', 'N/A')}\n"
                report += f"  * 피해 요약:\n"
                report += f"    {incident.get('summary', '피해 요약 정보가 없습니다.')}\n\n"
        else:
            report += "* 관련 사고 사례 정보가 없습니다.\n\n"
    
    report += "---\n\n## 5. 경영진 권고사항 (Management Engagement)\n\n"
    report += "> **목표**: **위험성**과 **유사 사고 사례**를 근거로 경영진이 **즉시/단기/중장기** 대책을 마련하도록 **설득**하는 메시지를 **5줄 이상** 작성\n\n"
    
    # 5. 경영진 권고사항
    for vuln in vuln_list:
        report += f"### {vuln.get('id', 'N/A')} – {vuln.get('type', 'N/A')}\n\n"
        
        management = vuln.get('management', {})
        report += f"* **긴급 대응**: {management.get('urgent', '긴급 대응 방안이 없습니다.')}\n\n"
        report += f"* **단기(1~3개월)**: {management.get('short_term', '단기 대응 방안이 없습니다.')}\n\n"
        report += f"* **중장기(3개월 이상)**: {management.get('long_term', '중장기 대응 방안이 없습니다.')}\n\n"
    
    report += "---\n\n## 6. 메타인지 교육 제안 (Metacognition Training)\n\n"
    report += "> **목표**: 전직원 대상 메타인지 교육의 **필요성** 및 **교육 내용**(목표·커리큘럼·기대 효과)을 **10줄 이상** 상세 제시\n\n"
    
    # 6. 메타인지 교육 제안 (첫 번째 취약점의 metacognition 사용)
    if vuln_list:
        first_vuln = vuln_list[0]
        metacognition = first_vuln.get('metacognition', '메타인지 교육 정보가 없습니다.')
        report += f"{metacognition}\n\n"
    
    report += "---\n\n## 7. 보안교육·처벌 명확성 (Education & Punishment Clarity)\n\n"
    
    # 7. 보안교육·처벌 명확성
    report += f"""* **보안교육 강화**: 정기 보안 릴리즈 노트 배포, 교육 완료 시 인센티브 제공
* **처벌 명확성**: 위반 시 단계별 제재(경고→교육 이수→직무 배제) 프로세스 문서화 및 HR·ITSM 연계

---

## 8. 부록(Appendix)

* **원본 진단 이미지 파일**: {image_filename}
* **분석된 취약점 수**: {len(vuln_list)}개
* **보고서 생성 시간**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
* **분석 도구**: Vision-LLM (Gemini 1.5 Flash)

### 취약점 상세 데이터 (JSON)

```json
{json.dumps(vuln_list, ensure_ascii=False, indent=2)}
```

---

**보고서 생성 완료**: {today} {datetime.now().strftime("%H:%M:%S")}
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