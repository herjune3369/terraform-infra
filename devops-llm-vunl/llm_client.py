# llm_client.py

import openai
import json
import os
from typing import List, Dict
import sys


def enrich_vuln_details(vuln_list: List[Dict]) -> List[Dict]:
    """
    vuln_list: [
      {
        "id": str,
        "type": str,
        "severity": str,
        "module": str,
        "summary": str,
        "risk": "",
        "incident": {"name":"", "date":"", "summary":""}
      },
      ...
    ]
    """
    # OpenAI API 키 설정
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        print("Warning: OPENAI_API_KEY not found, using mock data", file=sys.stderr)
        return _enrich_with_mock_data(vuln_list)
    
    openai.api_key = api_key
    
    enriched = []
    for vuln in vuln_list:
        try:
            # 1) LLM 프롬프트 생성
            prompt = f"""
다음 웹 취약점 정보에 대해 두 가지를 JSON으로 반환해 주세요:

1) risk: 이 취약점이 실제 공격당할 경우 예상되는 피해 시나리오를 최소 5줄 이상 세밀하게 설명.
2) incident: 유사 해킹 사고 사례 1건. 사례명, 발생일, 피해 요약을 포함하여 최소 5줄 이상 상세히 기술.

취약점 정보:
- ID: {vuln['id']}
- 유형: {vuln['type']}
- 심각도: {vuln['severity']}
- 모듈/URL: {vuln['module']}
- 요약 설명: {vuln['summary']}

출력 형식:
```json
{{
  "risk": "…",
  "incident": {{
    "name": "…",
    "date": "YYYY-MM-DD",
    "summary": "…"
  }}
}}
```"""
            
            # 2) LLM 호출
            resp = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=1000
            )
            content = resp.choices[0].message.content.strip()
            
            # 3) JSON 파싱
            data = _parse_llm_response(content)
            
            # 4) vuln 필드 업데이트
            vuln["risk"] = data.get("risk", "")
            vuln["incident"] = data.get("incident", {"name": "", "date": "", "summary": ""})
            enriched.append(vuln)
            
        except Exception as e:
            print(f"Error enriching vuln {vuln['id']}: {e}", file=sys.stderr)
            # 오류 발생 시 기본값으로 설정
            vuln["risk"] = f"{vuln['type']} 취약점은 심각한 보안 위험을 초래할 수 있습니다."
            vuln["incident"] = {
                "name": f"{vuln['type']} 관련 사고",
                "date": "2024-01-01",
                "summary": f"유사한 {vuln['type']} 취약점으로 인한 보안 사고가 발생했습니다."
            }
            enriched.append(vuln)

    return enriched


def _parse_llm_response(content: str) -> Dict:
    """LLM 응답에서 JSON 추출"""
    try:
        # JSON 블록 찾기
        if "```json" in content:
            start = content.find("```json") + 7
            end = content.find("```", start)
            json_str = content[start:end].strip()
        elif "```" in content:
            start = content.find("```") + 3
            end = content.find("```", start)
            json_str = content[start:end].strip()
        else:
            json_str = content.strip()
        
        # JSON 파싱
        data = json.loads(json_str)
        return data
        
    except Exception as e:
        print(f"Error parsing LLM response: {e}", file=sys.stderr)
        return {"risk": "", "incident": {"name": "", "date": "", "summary": ""}}


def _enrich_with_mock_data(vuln_list: List[Dict]) -> List[Dict]:
    """API 키가 없을 때 사용할 mock 데이터"""
    mock_risks = {
        "SQL Injection": "SQL Injection 취약점은 매우 심각한 위험을 초래합니다. 공격자가 이 취약점을 악용하여 데이터베이스에 무단으로 접근하여 모든 데이터를 탈취할 수 있습니다. 이는 개인정보 유출, 금융 정보 유출, 기업 기밀 유출 등으로 이어질 수 있으며, 심각한 재정적 손실과 명예 실추를 초래할 수 있습니다. 또한, 데이터베이스 서버 자체를 장악하여 시스템 전체를 마비시키거나 다른 시스템으로 공격을 확산시킬 수 있습니다.",
        "XSS": "Cross-Site Scripting 취약점은 공격자가 악성 스크립트를 웹 페이지에 삽입하여 사용자의 세션을 탈취하거나 개인정보를 유출시킬 수 있습니다. 이 취약점을 통해 공격자는 사용자의 쿠키, 세션 토큰, 개인정보 등을 가로채어 계정을 장악할 수 있습니다. 또한, 악성 리디렉션을 통해 피싱 사이트로 유도하거나 키로깅을 통해 민감한 정보를 수집할 수 있습니다.",
        "File Upload": "파일 업로드 취약점은 공격자가 악성 파일을 서버에 업로드하여 원격 코드 실행 권한을 획득할 수 있습니다. 업로드된 웹 셸을 통해 공격자는 서버를 완전히 장악하고, 내부 네트워크로 수평 이동하여 추가적인 시스템을 공격할 수 있습니다. 또한, 랜섬웨어를 배포하거나 백업 데이터를 암호화하여 복구를 방해할 수 있습니다."
    }
    
    mock_incidents = {
        "SQL Injection": {
            "name": "대형 쇼핑몰 SQL Injection 사고",
            "date": "2023-09-15",
            "summary": "대형 온라인 쇼핑몰에서 SQL Injection 취약점을 악용한 공격이 발생했습니다. 공격자는 로그인 페이지의 취약점을 통해 데이터베이스에 무단 접근하여 약 50만 명의 고객 개인정보를 유출시켰습니다. 이 사고로 인해 기업은 막대한 벌금을 부과받았고, 고객 신뢰도가 급격히 하락했습니다."
        },
        "XSS": {
            "name": "소셜 미디어 XSS 공격 사고",
            "date": "2024-02-20",
            "summary": "인기 소셜 미디어 플랫폼에서 XSS 취약점을 악용한 대규모 공격이 발생했습니다. 공격자는 댓글 기능에 악성 스크립트를 삽입하여 수천 명의 사용자 세션을 탈취했습니다. 탈취된 세션을 통해 개인정보가 유출되었고, 가짜 뉴스가 대량으로 확산되어 사회적 혼란을 야기했습니다."
        },
        "File Upload": {
            "name": "클라우드 스토리지 랜섬웨어 공격",
            "date": "2023-11-10",
            "summary": "클라우드 파일 공유 서비스에서 파일 업로드 취약점을 악용한 랜섬웨어 공격이 발생했습니다. 공격자는 악성 파일을 업로드하여 서버에 웹 셸을 설치하고, 내부 네트워크의 모든 파일을 암호화했습니다. 이로 인해 수천 개의 기업 데이터가 손실되었고, 서비스가 일주일간 중단되었습니다."
        }
    }
    
    enriched = []
    for vuln in vuln_list:
        vuln_type = vuln['type']
        
        # 위험성 설정
        vuln["risk"] = mock_risks.get(vuln_type, f"{vuln_type} 취약점은 심각한 보안 위험을 초래할 수 있습니다.")
        
        # 사고 사례 설정
        vuln["incident"] = mock_incidents.get(vuln_type, {
            "name": f"{vuln_type} 관련 사고",
            "date": "2024-01-01",
            "summary": f"유사한 {vuln_type} 취약점으로 인한 보안 사고가 발생했습니다."
        })
        
        enriched.append(vuln)
    
    return enriched


# 테스트 함수
def test_enrich_vuln_details():
    """enrich_vuln_details 함수 테스트"""
    test_vuln_list = [
        {
            "id": "VULN-001",
            "type": "SQL Injection",
            "severity": "높음",
            "module": "/login.php",
            "summary": "로그인 페이지에서 SQL Injection 취약점 발견",
            "risk": "",
            "incident": {"name": "", "date": "", "summary": ""}
        },
        {
            "id": "VULN-002",
            "type": "XSS",
            "severity": "중간",
            "module": "/comment.php",
            "summary": "댓글 기능에서 XSS 취약점 발견",
            "risk": "",
            "incident": {"name": "", "date": "", "summary": ""}
        }
    ]
    
    print("Testing enrich_vuln_details...")
    enriched = enrich_vuln_details(test_vuln_list)
    
    for vuln in enriched:
        print(f"\n{vuln['id']} - {vuln['type']}")
        print(f"Risk: {vuln['risk'][:100]}...")
        print(f"Incident: {vuln['incident']['name']}")


if __name__ == "__main__":
    test_enrich_vuln_details() 