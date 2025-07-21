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
            prompt = """
            아래 웹 취약점 진단 이미지를 분석해,
            • id: 취약점 고유번호
            • type: 취약점 유형
            • incidents: 유사 해킹 사고 사례 2건(사례명, 날짜, 요약)
            • risk: 해킹 시 예상 피해 시나리오
            • management: 위험 수준별(urgent/short_term/long_term) 대책 제안
            • metacognition: 메타인지 교육 필요성 및 주제
            를 JSON 배열로 반환해줘.
            
            실제 사례를 바탕으로 구체적이고 실용적인 정보를 제공해주세요.
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
                    "temperature": 0.3,
                    "topK": 40,
                    "topP": 0.95,
                    "maxOutputTokens": 2048
                }
            }
            
            # API 호출
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
            
            # LLM 응답 추출
            if "candidates" not in response_data or not response_data["candidates"]:
                raise Exception("LLM 응답에서 candidates를 찾을 수 없습니다.")
            
            llm_response = response_data["candidates"][0]["content"]["parts"][0]["text"]
            
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
            # JSON 블록 추출 (```json ... ``` 형태)
            if "```json" in llm_response:
                json_start = llm_response.find("```json") + 7
                json_end = llm_response.find("```", json_start)
                json_str = llm_response[json_start:json_end].strip()
            elif "```" in llm_response:
                # 일반 코드 블록에서 JSON 추출
                json_start = llm_response.find("```") + 3
                json_end = llm_response.find("```", json_start)
                json_str = llm_response[json_start:json_end].strip()
            else:
                # JSON 블록이 없는 경우 전체 텍스트에서 JSON 추출
                json_str = llm_response.strip()
            
            # JSON 파싱
            parsed_data = json.loads(json_str)
            
            # 배열이 아닌 경우 배열로 변환
            if not isinstance(parsed_data, list):
                parsed_data = [parsed_data]
            
            # 각 항목 검증 및 정규화
            validated_results = []
            for item in parsed_data:
                validated_item = self._validate_and_normalize_item(item)
                if validated_item:
                    validated_results.append(validated_item)
            
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
            # 필수 필드 검증
            required_fields = ['id', 'type', 'incidents', 'risk', 'management', 'metacognition']
            for field in required_fields:
                if field not in item:
                    print(f"경고: 필수 필드 '{field}'가 누락되었습니다.")
                    return None
            
            # 정규화된 구조로 변환
            normalized_item = {
                "id": str(item.get('id', 'VULN-UNKNOWN')),
                "type": str(item.get('type', 'Unknown')),
                "incidents": self._normalize_incidents(item.get('incidents', [])),
                "risk": str(item.get('risk', '')),
                "management": self._normalize_management(item.get('management', {})),
                "metacognition": str(item.get('metacognition', ''))
            }
            
            return normalized_item
            
        except Exception as e:
            print(f"항목 정규화 실패: {str(e)}")
            return None
    
    def _normalize_incidents(self, incidents: Union[List, str]) -> List[Dict]:
        """사고 사례 데이터 정규화"""
        if isinstance(incidents, str):
            return [{"title": "사고 사례", "date": "N/A", "summary": incidents}]
        
        if not isinstance(incidents, list):
            return []
        
        normalized_incidents = []
        for incident in incidents:
            if isinstance(incident, dict):
                normalized_incidents.append({
                    "title": str(incident.get('title', incident.get('사례명', 'Unknown'))),
                    "date": str(incident.get('date', incident.get('날짜', 'N/A'))),
                    "summary": str(incident.get('summary', incident.get('요약', '')))
                })
            elif isinstance(incident, str):
                normalized_incidents.append({
                    "title": "사고 사례",
                    "date": "N/A",
                    "summary": incident
                })
        
        return normalized_incidents
    
    def _normalize_management(self, management: Union[Dict, str]) -> Dict:
        """관리 대책 데이터 정규화"""
        if isinstance(management, str):
            return {
                "urgent": management,
                "short_term": management,
                "long_term": management
            }
        
        if not isinstance(management, dict):
            return {
                "urgent": "",
                "short_term": "",
                "long_term": ""
            }
        
        return {
            "urgent": str(management.get('urgent', management.get('즉시', ''))),
            "short_term": str(management.get('short_term', management.get('단기', ''))),
            "long_term": str(management.get('long_term', management.get('장기', '')))
        }
    
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