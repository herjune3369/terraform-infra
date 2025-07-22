# report_formatter.py

from typing import List, Dict


class ReportFormatter:
    """보고서 포매터 클래스"""
    
    @staticmethod
    def format_vuln_report(vuln_list: List[Dict], metadata: Dict) -> str:
        """
        vuln_list: [
          {
            "id": str,
            "type": str,
            "severity": str,
            "module": str,
            "summary": str,
            "risk": str,
            "incident": {
              "name": str,
              "date": str,
              "summary": str
            }
          },
          ...
        ]
        metadata: {
          "date": "YYYY-MM-DD",
          "author": str,
          "targetSystem": str
        }
        returns: Markdown report as a single string
        """
        
        # 1. 제목
        report = "# 전체 취약점 종합 진단 보고서\n\n"
        
        # 2. 보고서 개요
        report += "## 1. 보고서 개요\n"
        report += f"- **작성일**: {metadata.get('date', 'N/A')}\n"
        report += f"- **작성자/팀**: {metadata.get('author', 'N/A')}\n"
        report += f"- **대상 시스템**: {metadata.get('targetSystem', 'N/A')}\n"
        report += "- **보고 목적**: 진단된 취약점을 통해 조직원의 보안정책 준수 의지를 강화하고, 보호동기 이론(PMT) 기반 실행 전략을 제시\n\n"
        
        # 3. 구분선
        report += "---\n\n"
        
        # 4. 취약점 요약 Table
        report += "## 2. 취약점 요약 Table\n"
        report += "| 취약점 ID | 유형 | 심각도 | 발견 모듈/URL | 요약 설명 |\n"
        report += "|----------|------|-------|---------------|-----------|\n"
        
        for vuln in vuln_list:
            report += f"| {vuln.get('id', 'N/A')} | {vuln.get('type', 'N/A')} | {vuln.get('severity', 'N/A')} | {vuln.get('module', 'N/A')} | {vuln.get('summary', 'N/A')} |\n"
        
        report += "\n"
        
        # 5. 구분선
        report += "---\n\n"
        
        # 6. 취약점별 위험성 및 유사 해킹 사고 사례
        report += "## 3. 취약점별 위험성 및 유사 해킹 사고 사례\n"
        
        for vuln in vuln_list:
            report += f"### {vuln.get('type', 'N/A')}\n"
            report += f"**위험성**\n"
            report += f"{vuln.get('risk', 'N/A')}\n\n"
            
            incident = vuln.get('incident', {})
            report += f"**유사 해킹 사고 사례**\n"
            report += f"**{incident.get('name', 'N/A')} ({incident.get('date', 'N/A')})**\n"
            report += f"{incident.get('summary', 'N/A')}\n\n"
        
        # 7. 구분선
        report += "---\n\n"
        
        # 8. 경영진 보고사항 (Management Brief)
        report += "## 4. 경영진 보고사항 (APT 공격 시나리오 및 대응)\n"
        report += "공격자는 인증 우회 → 웹 셸 업로드 → 세션 탈취 → 설정 변경 → 랜섬웨어/데이터 유출의 흐름으로 시스템을 완전 장악할 수 있습니다.\n"
        report += "- **즉시 대응 (0–7일)**: 모든 취약점 엔드포인트 차단 및 WAF 규칙 적용 후 24시간 내 패치 완료\n"
        report += "- **단기 강화 (1–3주)**: 전사 코드 리뷰 및 자동화 스캔 도구 도입, 전 직원 모의 해킹 교육\n"
        report += "- **중장기 체계화 (1–3개월+)**: 보안 KPI 설정·분기별 CISO 검토 회의 제도화, SOC·SIEM 고도화\n\n"
        
        # 9. 구분선
        report += "---\n\n"
        
        # 10. 메타인지 교육 제안 (Metacognition Training)
        report += "## 5. 메타인지 교육 제안 (Metacognition Training)\n"
        report += "**교육 목표**: '내가 보는 정보의 안전성'을 스스로 점검하고 이상 징후를 조기에 식별하도록 함\n"
        report += "**커리큘럼**:\n"
        report += "- 위협 모델링 워크숍: 실제 취약점 사례 분석 및 리스크 매핑\n"
        report += "- 모의해킹 실습: XSS·RCE 시나리오 구성 및 대응 경험\n"
        report += "- 인지 회고 세션: 탐지 과정 기록 후 팀별 피드백\n"
        report += "- 퀴즈 기반 점검: 비정형 취약점 탐지 능력 검증\n"
        report += "- 행동 체크리스트: 배포 전 필수 점검 리스트 실습\n"
        report += "**기대 효과**:\n"
        report += "- 취약점 탐지 속도 50% 단축\n"
        report += "- 자발적 보안 리포트 2배 증가\n"
        report += "- 사고 대응 시간 평균 40% 개선\n\n"
        
        # 11. 구분선
        report += "---\n\n"
        
        # 12. 종합 대응 로드맵 (Comprehensive Response Roadmap)
        report += "## 6. 종합 대응 로드맵 (Comprehensive Response Roadmap)\n"
        report += "| 단계       | 기간      | 주요 활동                                              | 담당 조직/팀      |\n"
        report += "|------------|----------|-------------------------------------------------------|------------------|\n"
        report += "| 긴급 대응  | 0–7일    | 취약점 패치 및 WAF 규칙 적용, 긴급 모의해킹               | 보안팀·개발팀·SOC |\n"
        report += "| 단기 강화  | 1–3주   | 코드 리뷰 및 스캔 자동화 도입, 전 직원 모의해킹 교육        | 개발팀·교육팀     |\n"
        report += "| 중기 체계화 | 1–3개월 | 보안 KPI 설정·분기별 CISO 회의 제도화, SOC·SIEM 고도화    | 전략팀·거버넌스팀  |\n"
        report += "| 장기 개선  | 3–6개월+| Red/Blue Team 훈련, 온프레미스 LLM 검토, 외부 인증 준비     | 보안전략팀·감사팀  |\n\n"
        
        # 13. 구분선
        report += "---\n\n"
        
        # 14. 부록 (Appendix)
        report += "## 7. 부록 (Appendix)\n"
        report += "- 원본 진단 이미지 목록\n"
        report += "- JSON 리포트 원본\n"
        report += "- OCR/LLM 호출 로그\n"
        
        return report


# 편의 함수
def format_vuln_report(vuln_list: List[Dict], metadata: Dict) -> str:
    """ReportFormatter.format_vuln_report의 편의 함수"""
    return ReportFormatter.format_vuln_report(vuln_list, metadata)


# 테스트 함수
def test_report_formatter():
    """ReportFormatter 테스트"""
    test_vuln_list = [
        {
            "id": "VULN-001",
            "type": "SQL Injection",
            "severity": "높음",
            "module": "/login.php",
            "summary": "로그인 페이지에서 SQL Injection 취약점 발견",
            "risk": "SQL Injection 취약점은 매우 심각한 위험을 초래합니다. 공격자가 이 취약점을 악용하여 데이터베이스에 무단으로 접근하여 모든 데이터를 탈취할 수 있습니다.",
            "incident": {
                "name": "대형 쇼핑몰 SQL Injection 사고",
                "date": "2023-09-15",
                "summary": "대형 온라인 쇼핑몰에서 SQL Injection 취약점을 악용한 공격이 발생했습니다."
            }
        },
        {
            "id": "VULN-002",
            "type": "XSS",
            "severity": "중간",
            "module": "/comment.php",
            "summary": "댓글 기능에서 XSS 취약점 발견",
            "risk": "Cross-Site Scripting 취약점은 공격자가 악성 스크립트를 웹 페이지에 삽입하여 사용자의 세션을 탈취하거나 개인정보를 유출시킬 수 있습니다.",
            "incident": {
                "name": "소셜 미디어 XSS 공격 사고",
                "date": "2024-02-20",
                "summary": "인기 소셜 미디어 플랫폼에서 XSS 취약점을 악용한 대규모 공격이 발생했습니다."
            }
        }
    ]
    
    test_metadata = {
        "date": "2024-12-19",
        "author": "보안진단팀",
        "targetSystem": "웹 애플리케이션"
    }
    
    print("Testing ReportFormatter...")
    report = format_vuln_report(test_vuln_list, test_metadata)
    print(report)


if __name__ == "__main__":
    test_report_formatter() 