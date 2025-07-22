import os
import json
import base64
import requests
from typing import List, Dict, Optional, Union
from dotenv import load_dotenv

# 환경변수 로딩
load_dotenv()

class LLMClient:
    """Vision-capable LLM API 클라이언트"""
    
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY 환경변수가 설정되지 않았습니다.")
        
        self.base_url = "https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent"
        self.api_url = f"{self.base_url}?key={self.api_key}"
    
    def analyze_vuln_image(self, image_file, filename: str = None) -> List[Dict]:
        """
        웹 취약점 진단 이미지를 분석하여 PMT 기반 결과를 반환
        
        Args:
            image_file: 업로드된 이미지 파일 객체
            filename: 파일명 (선택사항)
            
        Returns:
            List[Dict]: 취약점 분석 결과 배열
            
        Raises:
            Exception: API 호출 실패 또는 파싱 오류 시
        """
        try:
            # 이미지를 base64로 인코딩
            image_data = image_file.read()
            encoded_image = base64.b64encode(image_data).decode('utf-8')
            
            # 파일 포인터를 처음으로 되돌림 (재사용을 위해)
            image_file.seek(0)
            
            # 파일명 처리
            if filename is None:
                filename = getattr(image_file, 'filename', 'unknown.jpg')
            
            # 프롬프트 템플릿
            prompt = f"""
            **중요**: 제공된 이미지를 자세히 분석하여 실제 발견된 취약점들을 식별해주세요.
            
            이미지에서 발견되는 웹 취약점들을 분석하여,
            **JSON 배열** 형태로 각 취약점별로 반환해 주세요.

            **분석 요구사항**:
            - 이미지에 표시된 실제 취약점들을 정확히 식별
            - 각 취약점의 구체적인 위치와 특성 분석
            - 발견된 취약점이 없다면 빈 배열 [] 반환

            **응답 형식**:
            [
              {{
                "id": "VULN-001",
                "type": "SQL Injection",
                "severity": "높음",
                "module": "/login",
                "summary": "로그인 폼에서 SQL Injection 취약점 발견",
                "incidents": [
                  {{
                    "name": "Equifax 데이터 유출 사고",
                    "date": "2017-05-13",
                    "summary": "Apache Struts 취약점을 이용한 대규모 데이터 유출. 1억 4,700만 명의 개인정보가 유출되었으며, 사회보장번호, 신용카드 정보, 운전면허증 번호 등 민감한 정보가 포함되었습니다. 공격자는 SQL Injection을 통해 데이터베이스에 직접 접근하여 모든 고객 정보를 탈취했습니다. 이 사고로 인해 회사는 약 7억 달러의 피해를 입었으며, CEO와 CSO가 사임하는 등 경영진 교체가 이루어졌습니다."
                  }},
                  {{
                    "name": "Heartland Payment Systems 해킹",
                    "date": "2008-03-19",
                    "summary": "SQL Injection을 통한 신용카드 정보 유출 사고. 공격자는 웹 애플리케이션의 취약점을 이용하여 데이터베이스에 접근하여 1억 3,400만 개의 신용카드 정보를 탈취했습니다. 이 사고는 미국 역사상 가장 큰 신용카드 정보 유출 사고 중 하나로 기록되었으며, 회사는 1억 4,100만 달러의 벌금을 부과받았습니다. 또한 고객 신뢰도 하락으로 인한 매출 감소와 브랜드 가치 하락을 경험했습니다."
                  }}
                ],
                "risk": "SQL Injection 취약점이 악용될 경우, 공격자는 데이터베이스에 직접 접근하여 모든 고객 정보를 탈취할 수 있습니다. 특히 개인정보, 금융정보, 비즈니스 데이터 등 민감한 정보가 노출될 위험이 매우 높습니다. 공격자는 데이터베이스 구조를 파악하고, 백업 데이터까지 접근하여 완전한 데이터 유출을 시도할 수 있습니다. 또한 데이터베이스 관리자 권한을 획득하여 시스템 전체를 장악할 가능성도 있습니다. 이는 단순한 데이터 유출을 넘어서 전체 비즈니스 운영의 중단으로 이어질 수 있는 심각한 위험입니다.",
                "management": {{
                  "urgent": "즉시 취약한 웹 애플리케이션의 패치를 적용하고, 모든 데이터베이스 접근을 차단해야 합니다. 또한 침입 탐지 시스템을 활성화하여 이상 징후를 모니터링하고, 영향을 받은 사용자들에게 즉시 통보해야 합니다.",
                  "short_term": "1-3개월 내에 웹 애플리케이션 방화벽(WAF)을 도입하고, 모든 입력값 검증 로직을 강화해야 합니다. 또한 정기적인 보안 취약점 점검을 실시하고, 개발자 대상 보안 코딩 교육을 진행해야 합니다.",
                  "long_term": "3개월 이상의 중장기 계획으로는 보안 개발 생명주기(SDLC) 도입, 자동화된 보안 테스트 도구 구축, 보안 인시던트 대응 체계 수립 등이 필요합니다. 또한 보안 문화 조성을 위한 전사적 보안 교육 프로그램을 운영해야 합니다."
                }},
                "metacognition": "전직원 대상 메타인지 교육은 보안 의식 향상과 위험 인식 능력 개발을 목표로 합니다. 교육 커리큘럼은 보안 위험 인식, 개인정보 보호 중요성, 사회공학적 공격 기법 이해, 안전한 웹 사용법 등을 포함합니다. 특히 개발팀은 안전한 코딩 방법론, 입력값 검증, SQL Injection 방지 기법 등을 심화 학습해야 합니다. 운영팀은 로그 모니터링, 이상 징후 감지, 사고 대응 절차 등을 교육받아야 합니다. 일반 직원들은 피싱 메일 식별, 안전한 비밀번호 관리, 개인정보 보호 수칙 등을 학습합니다. 이 교육을 통해 조직 전체의 보안 문화를 조성하고, 각 직원이 보안의 첫 번째 방어선 역할을 할 수 있도록 합니다."
              }}
            ]

            **주의사항**:
            - 이미지에서 실제로 발견된 취약점만 분석
            - 발견된 취약점이 없다면 빈 배열 [] 반환
            - 각 필드는 이미지 분석 결과를 바탕으로 작성
            - 일반적인 취약점 정보가 아닌 이미지 특정 분석 결과 제공
            """
            
            # API 요청 본문 구성
            request_body = {
                "contents": [
                    {
                        "role": "user",
                        "parts": [
                            {"text": prompt},
                            {
                                "inline_data": {
                                    "mime_type": self._get_mime_type(filename),
                                    "data": encoded_image
                                }
                            }
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.7,
                    "topK": 40,
                    "topP": 0.95,
                    "maxOutputTokens": 4096
                }
            }
            
            # API 호출
            print(f"DEBUG: API 호출 시작 - 파일명: {filename}")
            print(f"DEBUG: 이미지 크기: {len(image_data)} bytes")
            print(f"DEBUG: 인코딩된 이미지 길이: {len(encoded_image)}")
            
            headers = {"Content-Type": "application/json"}
            response = requests.post(
                self.api_url, 
                headers=headers, 
                json=request_body,
                timeout=60
            )
            
            # 응답 검증
            response.raise_for_status()
            response_data = response.json()
            
            print(f"DEBUG: API 응답 상태 코드: {response.status_code}")
            print(f"DEBUG: API 응답 키들: {list(response_data.keys())}")
            
            # LLM 응답 추출
            if "candidates" not in response_data or not response_data["candidates"]:
                print(f"DEBUG: 응답 데이터: {response_data}")
                raise Exception("LLM 응답에서 candidates를 찾을 수 없습니다.")
            
            llm_response = response_data["candidates"][0]["content"]["parts"][0]["text"]
            print(f"DEBUG: LLM 원본 응답 길이: {len(llm_response)}")
            print(f"DEBUG: LLM 응답 시작 부분: {llm_response[:300]}...")
            
            # JSON 파싱
            parsed_result = self._parse_llm_response(llm_response)
            
            return parsed_result
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"API 호출 실패: {str(e)}")
        except json.JSONDecodeError as e:
            raise Exception(f"JSON 파싱 실패: {str(e)}")
        except Exception as e:
            raise Exception(f"이미지 분석 실패: {str(e)}")
    
    def _get_mime_type(self, filename: str) -> str:
        """파일명에서 MIME 타입 추출"""
        if not filename:
            return "image/jpeg"
        
        ext = filename.lower().split('.')[-1]
        mime_types = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'bmp': 'image/bmp',
            'webp': 'image/webp'
        }
        
        return mime_types.get(ext, 'image/jpeg')
    
    def _parse_llm_response(self, llm_response: str) -> List[Dict]:
        """
        LLM 응답을 파싱하여 구조화된 데이터로 변환
        
        Args:
            llm_response: LLM의 원본 응답 텍스트
            
        Returns:
            List[Dict]: 파싱된 취약점 분석 결과 배열
        """
        try:
            print(f"DEBUG: LLM 응답 길이: {len(llm_response)}")
            print(f"DEBUG: LLM 응답 시작 부분: {llm_response[:200]}...")
            
            # JSON 블록 추출 (```json ... ``` 형태)
            json_str = None
            
            if "```json" in llm_response:
                json_start = llm_response.find("```json") + 7
                json_end = llm_response.find("```", json_start)
                if json_end > json_start:
                    json_str = llm_response[json_start:json_end].strip()
                    print("DEBUG: JSON 블록에서 추출됨")
            elif "```" in llm_response:
                # 일반 코드 블록에서 JSON 추출
                json_start = llm_response.find("```") + 3
                json_end = llm_response.find("```", json_start)
                if json_end > json_start:
                    json_str = llm_response[json_start:json_end].strip()
                    print("DEBUG: 일반 코드 블록에서 추출됨")
            
            # JSON 블록을 찾지 못한 경우, 대괄호로 시작하는 부분 찾기
            if not json_str:
                # [ 로 시작하는 부분 찾기
                start_idx = llm_response.find('[')
                if start_idx != -1:
                    # 짝이 맞는 ] 찾기
                    bracket_count = 0
                    end_idx = start_idx
                    for i, char in enumerate(llm_response[start_idx:], start_idx):
                        if char == '[':
                            bracket_count += 1
                        elif char == ']':
                            bracket_count -= 1
                            if bracket_count == 0:
                                end_idx = i + 1
                                break
                    
                    if end_idx > start_idx:
                        json_str = llm_response[start_idx:end_idx].strip()
                        print("DEBUG: 대괄호 패턴에서 추출됨")
            
            # 여전히 찾지 못한 경우 전체 텍스트 사용
            if not json_str:
                json_str = llm_response.strip()
                print("DEBUG: 전체 텍스트 사용")
            
            print(f"DEBUG: 추출된 JSON 문자열 길이: {len(json_str)}")
            print(f"DEBUG: 추출된 JSON 시작 부분: {json_str[:200]}...")
            
            # JSON 파싱 시도
            try:
                parsed_data = json.loads(json_str)
            except json.JSONDecodeError as e:
                print(f"DEBUG: JSON 파싱 실패, 오류: {str(e)}")
                print(f"DEBUG: 문제가 있는 JSON 문자열: {json_str}")
                
                # JSON 수정 시도
                # 1. 불필요한 공백 제거
                json_str = json_str.strip()
                
                # 2. 마지막 쉼표 제거
                if json_str.endswith(','):
                    json_str = json_str[:-1]
                
                # 3. 다시 파싱 시도
                try:
                    parsed_data = json.loads(json_str)
                    print("DEBUG: JSON 수정 후 파싱 성공")
                except json.JSONDecodeError as e2:
                    print(f"DEBUG: JSON 수정 후에도 파싱 실패: {str(e2)}")
                    raise e2
            
            # 배열이 아닌 경우 배열로 변환
            if not isinstance(parsed_data, list):
                parsed_data = [parsed_data]
            
            print(f"DEBUG: 파싱된 데이터 항목 수: {len(parsed_data)}")
            
            # 각 항목 검증 및 정규화
            validated_results = []
            for i, item in enumerate(parsed_data):
                print(f"DEBUG: 항목 {i+1} 검증 중...")
                validated_item = self._validate_and_normalize_item(item)
                if validated_item:
                    validated_results.append(validated_item)
                    print(f"DEBUG: 항목 {i+1} 검증 완료")
                else:
                    print(f"DEBUG: 항목 {i+1} 검증 실패")
            
            print(f"DEBUG: 최종 검증된 항목 수: {len(validated_results)}")
            return validated_results
            
        except json.JSONDecodeError as e:
            raise Exception(f"JSON 파싱 오류: {str(e)}")
        except Exception as e:
            raise Exception(f"응답 파싱 실패: {str(e)}")
    
    def _validate_and_normalize_item(self, item: Dict) -> Optional[Dict]:
        """
        개별 취약점 항목을 검증하고 정규화
        
        Args:
            item: 원본 취약점 데이터
            
        Returns:
            Optional[Dict]: 검증 및 정규화된 데이터
        """
        try:
            print(f"DEBUG: 검증할 항목: {item}")
            
            # 필수 필드 검증 (더 유연하게)
            missing_fields = []
            required_fields = ['id', 'type', 'incidents', 'risk', 'management', 'metacognition']
            
            for field in required_fields:
                if field not in item or not item[field]:
                    missing_fields.append(field)
            
            if missing_fields:
                print(f"경고: 누락된 필드들: {missing_fields}")
                # 누락된 필드에 기본값 설정
                for field in missing_fields:
                    if field == 'id':
                        item[field] = f"VULN-{len(missing_fields)}"
                    elif field == 'type':
                        item[field] = 'Unknown'
                    elif field == 'incidents':
                        item[field] = []
                    elif field == 'risk':
                        item[field] = '위험성 정보가 없습니다.'
                    elif field == 'management':
                        item[field] = {}
                    elif field == 'metacognition':
                        item[field] = '메타인지 교육 정보가 없습니다.'
            
            # 정규화된 구조로 변환
            normalized_item = {
                "id": str(item.get('id', 'VULN-UNKNOWN')),
                "type": str(item.get('type', 'Unknown')),
                "severity": str(item.get('severity', '중간')),
                "module": str(item.get('module', '/unknown')),
                "summary": str(item.get('summary', '취약점 요약 정보가 없습니다.')),
                "incidents": self._normalize_incidents(item.get('incidents', [])),
                "risk": str(item.get('risk', '위험성 정보가 없습니다.')),
                "management": self._normalize_management(item.get('management', {})),
                "metacognition": str(item.get('metacognition', '메타인지 교육 정보가 없습니다.'))
            }
            
            print(f"DEBUG: 정규화된 항목: {normalized_item}")
            return normalized_item
            
        except Exception as e:
            print(f"항목 정규화 실패: {str(e)}")
            return None
    
    def _normalize_incidents(self, incidents: Union[List, str]) -> List[Dict]:
        """사고 사례 데이터 정규화"""
        print(f"DEBUG: incidents 정규화 시작: {incidents}")
        
        if isinstance(incidents, str):
            print("DEBUG: incidents가 문자열입니다.")
            return [{"name": "사고 사례", "date": "N/A", "summary": incidents}]
        
        if not isinstance(incidents, list):
            print("DEBUG: incidents가 리스트가 아닙니다.")
            return []
        
        normalized_incidents = []
        for i, incident in enumerate(incidents):
            print(f"DEBUG: incident {i+1} 처리 중: {incident}")
            
            if isinstance(incident, dict):
                # 다양한 필드명 지원
                name = incident.get('name') or incident.get('title') or incident.get('사례명') or f"사고 사례 {i+1}"
                date = incident.get('date') or incident.get('날짜') or 'N/A'
                summary = incident.get('summary') or incident.get('요약') or '피해 요약 정보가 없습니다.'
                
                normalized_incidents.append({
                    "name": str(name),
                    "date": str(date),
                    "summary": str(summary)
                })
                print(f"DEBUG: incident {i+1} 정규화 완료")
            elif isinstance(incident, str):
                normalized_incidents.append({
                    "name": f"사고 사례 {i+1}",
                    "date": "N/A",
                    "summary": incident
                })
                print(f"DEBUG: incident {i+1} 문자열 처리 완료")
        
        print(f"DEBUG: 정규화된 incidents: {normalized_incidents}")
        return normalized_incidents
    
    def _normalize_management(self, management: Union[Dict, str]) -> Dict:
        """관리 대책 데이터 정규화"""
        print(f"DEBUG: management 정규화 시작: {management}")
        
        if isinstance(management, str):
            print("DEBUG: management가 문자열입니다.")
            return {
                "urgent": management,
                "short_term": management,
                "long_term": management
            }
        
        if not isinstance(management, dict):
            print("DEBUG: management가 딕셔너리가 아닙니다.")
            return {
                "urgent": "긴급 대응 방안이 없습니다.",
                "short_term": "단기 대응 방안이 없습니다.",
                "long_term": "중장기 대응 방안이 없습니다."
            }
        
        # 다양한 필드명 지원
        urgent = management.get('urgent') or management.get('즉시') or management.get('긴급') or '긴급 대응 방안이 없습니다.'
        short_term = management.get('short_term') or management.get('단기') or management.get('short') or '단기 대응 방안이 없습니다.'
        long_term = management.get('long_term') or management.get('장기') or management.get('long') or '중장기 대응 방안이 없습니다.'
        
        normalized_management = {
            "urgent": str(urgent),
            "short_term": str(short_term),
            "long_term": str(long_term)
        }
        
        print(f"DEBUG: 정규화된 management: {normalized_management}")
        return normalized_management
    
    def test_connection(self) -> bool:
        """API 연결 테스트"""
        try:
            headers = {"Content-Type": "application/json"}
            test_body = {
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": "Hello, this is a test."}]
                    }
                ]
            }
            
            response = requests.post(
                self.api_url,
                headers=headers,
                json=test_body,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception:
            return False


# 사용 예시
if __name__ == "__main__":
    # 클라이언트 초기화
    client = LLMClient()
    
    # 연결 테스트
    if client.test_connection():
        print("✅ LLM API 연결 성공")
    else:
        print("❌ LLM API 연결 실패")
    
    # 실제 사용 예시 (파일이 있는 경우)
    # with open('vuln_image.jpg', 'rb') as f:
    #     results = client.analyze_vuln_image(f)
    #     print(json.dumps(results, indent=2, ensure_ascii=False)) 