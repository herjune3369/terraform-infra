import json
from datetime import datetime
from typing import List, Dict, Optional

class ReportGenerator:
    """보안 취약점 준수 강화 리포트 생성기"""
    
    def __init__(self):
        self.template = self._load_template()
    
    def _load_template(self) -> str:
        """Markdown 템플릿 로드"""
        return """# ▶ 최종 보안 취약점 준수 강화 리포트

## 1. 보고서 개요

* **작성일**: {report_date}
* **작성자/팀**: DevOps LLM VUNL System
* **대상 시스템**: {target_system}
* **보고 목적**: "진단된 취약점이 조직원의 보안정책 준수 의지에 미치는 영향을 최소화하고, 보호동기 강화 실행 전략 제시"

---

## 2. 취약점 요약 Table

| 취약점 ID | 유형 | 심각도 | 발견 모듈/URL | 요약 설명 |
|-----------|------|--------|---------------|-----------|
{vulnerability_table}

---

## 3. 지각된 위험성 (Perceived Risk)

> **목표**: 해당 취약점이 조직에 줄 수 있는 **구체적·치명적 피해**를 **5줄 이상** 상세히 기술

{risk_section}

---

## 4. 유사 해킹 사고 사례 (Incident Case Studies)

> **목표**: **각 사례마다** 사례 개요·발생 경위·피해 규모를 **5줄 이상**으로 상세하게 설명

{incidents_section}

---

## 5. 경영진 권고사항 (Management Engagement)

> **목표**: **위험성**과 **유사 사고 사례**를 근거로 경영진이 **즉시/단기/중장기** 대책을 마련하도록 **설득**하는 메시지를 **5줄 이상** 작성

{management_section}

---

## 6. 메타인지 교육 제안 (Metacognition Training)

> **목표**: 전직원 대상 메타인지 교육의 **필요성** 및 **교육 내용**(목표·커리큘럼·기대 효과)을 **10줄 이상** 상세 제시

{metacognition_section}

---

## 7. 보안교육·처벌 명확성 (Education & Punishment Clarity)

* **보안교육 강화**: 정기 보안 릴리즈 노트 배포, 교육 완료 시 인센티브 제공
* **처벌 명확성**: 위반 시 단계별 제재(경고→교육 이수→직무 배제) 프로세스 문서화 및 HR·ITSM 연계

---

## 8. 부록(Appendix)

* **원본 진단 이미지 파일**: {image_filename}
* **전체 JSON 리포트 원본**: {json_data}
* **생성 시간**: {generation_time}
"""
    
    def generate_report(self, vuln_list: List[Dict], target_system: str = "웹 애플리케이션", 
                       image_filename: str = "unknown.jpg") -> str:
        """
        Markdown 형식의 최종 보고서 생성
        
        Args:
            vuln_list: 취약점 분석 결과 배열
            target_system: 대상 시스템명
            image_filename: 원본 이미지 파일명
            
        Returns:
            str: Markdown 형식의 보고서
        """
        try:
            # 현재 날짜
            report_date = datetime.now().strftime("%Y년 %m월 %d일")
            generation_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # 취약점 테이블 생성
            vulnerability_table = self._generate_vulnerability_table(vuln_list)
            
            # 위험성 섹션 생성
            risk_section = self._generate_risk_section(vuln_list)
            
            # 사고 사례 섹션 생성
            incidents_section = self._generate_incidents_section(vuln_list)
            
            # 경영진 권고사항 섹션 생성
            management_section = self._generate_management_section(vuln_list)
            
            # 메타인지 교육 섹션 생성
            metacognition_section = self._generate_metacognition_section(vuln_list)
            
            # JSON 데이터 (축약형)
            json_data = json.dumps(vuln_list, ensure_ascii=False, indent=2)[:500] + "..."
            
            # 템플릿에 데이터 삽입
            report = self.template.format(
                report_date=report_date,
                target_system=target_system,
                vulnerability_table=vulnerability_table,
                risk_section=risk_section,
                incidents_section=incidents_section,
                management_section=management_section,
                metacognition_section=metacognition_section,
                image_filename=image_filename,
                json_data=json_data,
                generation_time=generation_time
            )
            
            return report
            
        except Exception as e:
            raise Exception(f"보고서 생성 실패: {str(e)}")
    
    def _generate_vulnerability_table(self, vuln_list: List[Dict]) -> str:
        """취약점 요약 테이블 생성"""
        table_rows = []
        for vuln in vuln_list:
            row = f"| {vuln.get('id', 'N/A')} | {vuln.get('type', 'N/A')} | {vuln.get('severity', 'N/A')} | {vuln.get('module', 'N/A')} | {vuln.get('summary', 'N/A')} |"
            table_rows.append(row)
        
        return "\n".join(table_rows)
    
    def _generate_risk_section(self, vuln_list: List[Dict]) -> str:
        """위험성 섹션 생성"""
        risk_content = []
        for vuln in vuln_list:
            risk_content.append(f"""
### {vuln.get('id', 'N/A')} – {vuln.get('type', 'N/A')}

{vuln.get('risk', '위험성 정보가 없습니다.')}
""")
        
        return "\n".join(risk_content)
    
    def _generate_incidents_section(self, vuln_list: List[Dict]) -> str:
        """사고 사례 섹션 생성"""
        incidents_content = []
        for vuln in vuln_list:
            vuln_incidents = []
            vuln_incidents.append(f"### {vuln.get('id', 'N/A')} – {vuln.get('type', 'N/A')}")
            
            incidents = vuln.get('incidents', [])
            for i, incident in enumerate(incidents, 1):
                vuln_incidents.append(f"""
* **사례명**: {incident.get('name', 'N/A')}
* **발생일**: {incident.get('date', 'N/A')}
* **피해 요약**:
  {incident.get('summary', '피해 요약 정보가 없습니다.')}
""")
            
            incidents_content.append("\n".join(vuln_incidents))
        
        return "\n".join(incidents_content)
    
    def _generate_management_section(self, vuln_list: List[Dict]) -> str:
        """경영진 권고사항 섹션 생성"""
        management_content = []
        for vuln in vuln_list:
            management = vuln.get('management', {})
            
            # management가 문자열인 경우 처리
            if isinstance(management, str):
                management_content.append(f"""
### {vuln.get('id', 'N/A')} – {vuln.get('type', 'N/A')}

{management}
""")
            else:
                # management가 객체인 경우
                management_content.append(f"""
### {vuln.get('id', 'N/A')} – {vuln.get('type', 'N/A')}

* **긴급 대응**: {management.get('urgent', '긴급 대응 방안이 없습니다.')}
* **단기(1~3개월)**: {management.get('short_term', '단기 대응 방안이 없습니다.')}
* **중장기(3개월 이상)**: {management.get('long_term', '중장기 대응 방안이 없습니다.')}
""")
        
        return "\n".join(management_content)
    
    def _generate_metacognition_section(self, vuln_list: List[Dict]) -> str:
        """메타인지 교육 섹션 생성"""
        if not vuln_list:
            return "메타인지 교육 정보가 없습니다."
        
        # 첫 번째 취약점의 메타인지 정보 사용 (또는 모든 것을 병합)
        metacognition = vuln_list[0].get('metacognition', '메타인지 교육 정보가 없습니다.')
        
        return f"""
{metacognition}
"""

# 전역 인스턴스 생성
report_generator = ReportGenerator()

def generate_final_report(vuln_list: List[Dict], target_system: str = "웹 애플리케이션", 
                         image_filename: str = "unknown.jpg") -> str:
    """최종 보고서 생성 편의 함수"""
    return report_generator.generate_report(vuln_list, target_system, image_filename) 