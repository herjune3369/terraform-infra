#!/usr/bin/env python3
"""
엔드포인트 모의 테스트 스크립트
"""

import os
import sys
import json
from unittest.mock import patch, MagicMock

# Flask 앱 디렉토리를 Python 경로에 추가
sys.path.append('ansible/roles/flask/files')

def test_endpoint_with_mock_data():
    """모의 데이터로 엔드포인트 테스트"""
    print("🔍 엔드포인트 모의 테스트")
    print("=" * 50)
    
    try:
        from app import app
        
        # 모의 데이터 생성
        mock_report_data = {
            "report_id": "test-uuid-1234",
            "image_filename": "test-image.jpg",
            "created_at": "2024-01-01T12:00:00",
            "vulnerabilities": [
                {
                    "vuln_id": "VULN-001",
                    "type": "SQL Injection",
                    "incidents": [
                        {
                            "title": "Test Incident 1",
                            "date": "2023-01-15",
                            "summary": "SQL Injection attack on login page"
                        }
                    ],
                    "risk": "High risk of data breach",
                    "management": {
                        "urgent": "Block vulnerable endpoint",
                        "short_term": "Implement input validation",
                        "long_term": "Regular security audits"
                    },
                    "metacognition": "Developers need security training"
                },
                {
                    "vuln_id": "VULN-002",
                    "type": "XSS",
                    "incidents": [
                        {
                            "title": "Test Incident 2",
                            "date": "2023-02-20",
                            "summary": "Cross-site scripting attack"
                        }
                    ],
                    "risk": "Medium risk of session hijacking",
                    "management": {
                        "urgent": "Sanitize user inputs",
                        "short_term": "Implement CSP headers",
                        "long_term": "Code review process"
                    },
                    "metacognition": "Frontend developers need XSS awareness"
                }
            ]
        }
        
        # get_report 함수를 모의로 대체
        with patch('app.get_report') as mock_get_report:
            
            # 1. 존재하지 않는 report_id 테스트
            print("1️⃣ 존재하지 않는 report_id 테스트...")
            mock_get_report.return_value = None
            
            with app.test_client() as client:
                response = client.get('/api/vuln/report/non-existent-id')
                print(f"   상태 코드: {response.status_code}")
                print(f"   응답: {response.get_json()}")
                
                if response.status_code == 404:
                    print("   ✅ 404 응답 정상")
                else:
                    print("   ❌ 예상과 다른 응답")
            
            print()
            
            # 2. 유효한 report_id 테스트
            print("2️⃣ 유효한 report_id 테스트...")
            mock_get_report.return_value = mock_report_data
            
            with app.test_client() as client:
                response = client.get('/api/vuln/report/test-uuid-1234')
                print(f"   상태 코드: {response.status_code}")
                print(f"   응답: {response.get_json()}")
                
                if response.status_code == 200:
                    print("   ✅ 200 응답 정상")
                    data = response.get_json()
                    if isinstance(data, list):
                        print("   ✅ 배열 형태 응답 정상")
                        print(f"   📊 취약점 개수: {len(data)}")
                        
                        # 첫 번째 취약점 검증
                        if len(data) > 0:
                            first_vuln = data[0]
                            required_fields = ['vuln_id', 'type', 'incidents', 'risk', 'management', 'metacognition']
                            missing_fields = [field for field in required_fields if field not in first_vuln]
                            
                            if not missing_fields:
                                print("   ✅ 모든 필수 필드 포함")
                            else:
                                print(f"   ❌ 누락된 필드: {missing_fields}")
                    else:
                        print("   ❌ 배열 형태가 아님")
                else:
                    print("   ❌ 예상과 다른 응답")
            
            print()
            
            # 3. 예외 발생 테스트
            print("3️⃣ 예외 발생 테스트...")
            mock_get_report.side_effect = Exception("Database connection failed")
            
            with app.test_client() as client:
                response = client.get('/api/vuln/report/test-uuid-1234')
                print(f"   상태 코드: {response.status_code}")
                print(f"   응답: {response.get_json()}")
                
                if response.status_code == 500:
                    print("   ✅ 500 응답 정상")
                else:
                    print("   ❌ 예상과 다른 응답")
        
        return True
        
    except ImportError as e:
        print(f"❌ Flask 앱 임포트 실패: {str(e)}")
        return False
    except Exception as e:
        print(f"❌ 테스트 실패: {str(e)}")
        return False

def test_endpoint_logic_flow():
    """엔드포인트 로직 흐름 테스트"""
    print("🔍 엔드포인트 로직 흐름 테스트")
    print("=" * 50)
    
    try:
        from app import app
        
        # 테스트 케이스들
        test_cases = [
            {
                "name": "존재하지 않는 report_id",
                "report_id": "non-existent-id",
                "mock_return": None,
                "expected_status": 404,
                "expected_error": "Report not found"
            },
            {
                "name": "빈 문자열 report_id",
                "report_id": "",
                "mock_return": None,
                "expected_status": 404,
                "expected_error": "Report not found"
            },
            {
                "name": "특수문자 포함 report_id",
                "report_id": "test@#$%^&*()",
                "mock_return": None,
                "expected_status": 404,
                "expected_error": "Report not found"
            },
            {
                "name": "긴 report_id",
                "report_id": "a" * 100,
                "mock_return": None,
                "expected_status": 404,
                "expected_error": "Report not found"
            }
        ]
        
        with patch('app.get_report') as mock_get_report:
            with app.test_client() as client:
                for i, test_case in enumerate(test_cases, 1):
                    print(f"{i}️⃣ {test_case['name']} 테스트...")
                    
                    mock_get_report.return_value = test_case['mock_return']
                    
                    response = client.get(f'/api/vuln/report/{test_case["report_id"]}')
                    print(f"   상태 코드: {response.status_code}")
                    print(f"   응답: {response.get_json()}")
                    
                    if response.status_code == test_case['expected_status']:
                        print("   ✅ 상태 코드 정상")
                        
                        if test_case['expected_status'] == 404:
                            response_data = response.get_json()
                            if 'error' in response_data and test_case['expected_error'] in response_data['error']:
                                print("   ✅ 에러 메시지 정상")
                            else:
                                print("   ❌ 에러 메시지 불일치")
                    else:
                        print("   ❌ 상태 코드 불일치")
                    
                    print()
        
        return True
        
    except Exception as e:
        print(f"❌ 로직 흐름 테스트 실패: {str(e)}")
        return False

def test_response_format():
    """응답 형식 테스트"""
    print("🔍 응답 형식 테스트")
    print("=" * 50)
    
    try:
        from app import app
        
        # 다양한 형태의 모의 데이터
        test_data_sets = [
            {
                "name": "단일 취약점",
                "data": {
                    "report_id": "test-1",
                    "vulnerabilities": [
                        {
                            "vuln_id": "VULN-001",
                            "type": "SQL Injection",
                            "incidents": [],
                            "risk": "High",
                            "management": {},
                            "metacognition": "Training needed"
                        }
                    ]
                }
            },
            {
                "name": "다중 취약점",
                "data": {
                    "report_id": "test-2",
                    "vulnerabilities": [
                        {
                            "vuln_id": "VULN-001",
                            "type": "SQL Injection",
                            "incidents": [{"title": "Incident 1"}],
                            "risk": "High",
                            "management": {"urgent": "Fix now"},
                            "metacognition": "Training needed"
                        },
                        {
                            "vuln_id": "VULN-002",
                            "type": "XSS",
                            "incidents": [{"title": "Incident 2"}],
                            "risk": "Medium",
                            "management": {"short_term": "Fix soon"},
                            "metacognition": "Code review needed"
                        }
                    ]
                }
            },
            {
                "name": "빈 취약점 목록",
                "data": {
                    "report_id": "test-3",
                    "vulnerabilities": []
                }
            }
        ]
        
        with patch('app.get_report') as mock_get_report:
            with app.test_client() as client:
                for i, test_set in enumerate(test_data_sets, 1):
                    print(f"{i}️⃣ {test_set['name']} 테스트...")
                    
                    mock_get_report.return_value = test_set['data']
                    
                    response = client.get(f'/api/vuln/report/{test_set["data"]["report_id"]}')
                    print(f"   상태 코드: {response.status_code}")
                    
                    if response.status_code == 200:
                        data = response.get_json()
                        print(f"   응답 타입: {type(data)}")
                        print(f"   취약점 개수: {len(data)}")
                        
                        if isinstance(data, list):
                            print("   ✅ 배열 형태 정상")
                            
                            # 각 취약점의 필수 필드 검증
                            for j, vuln in enumerate(data):
                                required_fields = ['vuln_id', 'type', 'incidents', 'risk', 'management', 'metacognition']
                                missing_fields = [field for field in required_fields if field not in vuln]
                                
                                if not missing_fields:
                                    print(f"   ✅ 취약점 {j+1} 필수 필드 완전")
                                else:
                                    print(f"   ❌ 취약점 {j+1} 누락 필드: {missing_fields}")
                        else:
                            print("   ❌ 배열 형태가 아님")
                    else:
                        print("   ❌ 예상과 다른 상태 코드")
                    
                    print()
        
        return True
        
    except Exception as e:
        print(f"❌ 응답 형식 테스트 실패: {str(e)}")
        return False

def main():
    """메인 테스트 함수"""
    print("🚀 엔드포인트 모의 테스트 시작")
    print("=" * 60)
    
    # 환경변수 설정
    os.environ['GEMINI_API_KEY'] = "AIzaSyB-lFb9w-Uy-sJtw31xlVx8ohnQpzNje4g"
    
    # 1. 기본 모의 테스트
    if test_endpoint_with_mock_data():
        print("✅ 기본 모의 테스트 통과")
    else:
        print("❌ 기본 모의 테스트 실패")
    
    print("\n" + "=" * 60)
    
    # 2. 로직 흐름 테스트
    if test_endpoint_logic_flow():
        print("✅ 로직 흐름 테스트 통과")
    else:
        print("❌ 로직 흐름 테스트 실패")
    
    print("\n" + "=" * 60)
    
    # 3. 응답 형식 테스트
    if test_response_format():
        print("✅ 응답 형식 테스트 통과")
    else:
        print("❌ 응답 형식 테스트 실패")
    
    print("\n✅ 모든 모의 테스트 완료!")

if __name__ == "__main__":
    main() 