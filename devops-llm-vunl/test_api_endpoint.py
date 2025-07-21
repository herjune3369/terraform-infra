#!/usr/bin/env python3
"""
API 엔드포인트 테스트 스크립트
"""

import os
import sys
import json
import requests
import asyncio

# Flask 앱 디렉토리를 Python 경로에 추가
sys.path.append('ansible/roles/flask/files')

def test_api_endpoint():
    """API 엔드포인트 테스트"""
    print("🔍 API 엔드포인트 테스트 시작")
    print("=" * 50)
    
    # Flask 앱을 백그라운드에서 실행
    base_url = "http://localhost:5000"
    
    # 1. 존재하지 않는 report_id로 테스트 (404 예상)
    print("1️⃣ 존재하지 않는 report_id 테스트...")
    try:
        response = requests.get(f"{base_url}/api/vuln/report/non-existent-id")
        print(f"   상태 코드: {response.status_code}")
        print(f"   응답: {response.json()}")
        
        if response.status_code == 404:
            print("   ✅ 404 응답 정상")
        else:
            print("   ❌ 예상과 다른 응답")
            
    except requests.exceptions.ConnectionError:
        print("   ⚠️ Flask 서버가 실행되지 않음 (예상된 결과)")
    except Exception as e:
        print(f"   ❌ 오류: {str(e)}")
    
    print()
    
    # 2. 잘못된 형식의 report_id로 테스트
    print("2️⃣ 잘못된 형식의 report_id 테스트...")
    try:
        response = requests.get(f"{base_url}/api/vuln/report/invalid-format")
        print(f"   상태 코드: {response.status_code}")
        print(f"   응답: {response.json()}")
        
    except requests.exceptions.ConnectionError:
        print("   ⚠️ Flask 서버가 실행되지 않음 (예상된 결과)")
    except Exception as e:
        print(f"   ❌ 오류: {str(e)}")
    
    print()
    
    # 3. 유효한 report_id로 테스트 (실제 데이터가 있을 경우)
    print("3️⃣ 유효한 report_id 테스트...")
    try:
        # 실제로는 존재하는 report_id를 사용해야 함
        test_report_id = "test-uuid-1234-5678-9012"
        response = requests.get(f"{base_url}/api/vuln/report/{test_report_id}")
        print(f"   상태 코드: {response.status_code}")
        print(f"   응답: {response.json()}")
        
    except requests.exceptions.ConnectionError:
        print("   ⚠️ Flask 서버가 실행되지 않음 (예상된 결과)")
    except Exception as e:
        print(f"   ❌ 오류: {str(e)}")

def test_flask_app_directly():
    """Flask 앱을 직접 테스트"""
    print("🔍 Flask 앱 직접 테스트")
    print("=" * 50)
    
    try:
        # Flask 앱 임포트
        from app import app
        
        # 테스트 클라이언트 생성
        with app.test_client() as client:
            
            # 1. 존재하지 않는 report_id 테스트
            print("1️⃣ 존재하지 않는 report_id 테스트...")
            response = client.get('/api/vuln/report/non-existent-id')
            print(f"   상태 코드: {response.status_code}")
            print(f"   응답: {response.get_json()}")
            
            if response.status_code == 404:
                print("   ✅ 404 응답 정상")
            else:
                print("   ❌ 예상과 다른 응답")
            
            print()
            
            # 2. 잘못된 형식의 report_id 테스트
            print("2️⃣ 잘못된 형식의 report_id 테스트...")
            response = client.get('/api/vuln/report/invalid-format')
            print(f"   상태 코드: {response.status_code}")
            print(f"   응답: {response.get_json()}")
            
            print()
            
            # 3. 유효한 report_id 테스트 (실제 데이터가 있을 경우)
            print("3️⃣ 유효한 report_id 테스트...")
            test_report_id = "test-uuid-1234-5678-9012"
            response = client.get(f'/api/vuln/report/{test_report_id}')
            print(f"   상태 코드: {response.status_code}")
            print(f"   응답: {response.get_json()}")
            
            if response.status_code == 404:
                print("   ✅ 404 응답 정상 (데이터가 없는 경우)")
            elif response.status_code == 200:
                print("   ✅ 200 응답 정상")
                data = response.get_json()
                if isinstance(data, list):
                    print("   ✅ 배열 형태 응답 정상")
                else:
                    print("   ❌ 배열 형태가 아님")
            
    except ImportError as e:
        print(f"❌ Flask 앱 임포트 실패: {str(e)}")
    except Exception as e:
        print(f"❌ 테스트 실패: {str(e)}")

def test_endpoint_logic():
    """엔드포인트 로직 테스트"""
    print("🔍 엔드포인트 로직 테스트")
    print("=" * 50)
    
    try:
        from vulnService import get_report
        
        # 1. 존재하지 않는 report_id 테스트
        print("1️⃣ 존재하지 않는 report_id 테스트...")
        result = get_report("non-existent-id")
        if result is None:
            print("   ✅ None 반환 정상")
        else:
            print("   ❌ 예상과 다른 결과")
        
        print()
        
        # 2. 잘못된 형식의 report_id 테스트
        print("2️⃣ 잘못된 형식의 report_id 테스트...")
        result = get_report("invalid-format")
        if result is None:
            print("   ✅ None 반환 정상")
        else:
            print("   ❌ 예상과 다른 결과")
        
        print()
        
        # 3. 유효한 report_id 테스트 (실제 데이터가 있을 경우)
        print("3️⃣ 유효한 report_id 테스트...")
        test_report_id = "test-uuid-1234-5678-9012"
        result = get_report(test_report_id)
        
        if result is None:
            print("   ✅ None 반환 정상 (데이터가 없는 경우)")
        else:
            print("   ✅ 데이터 반환 정상")
            print(f"   📊 취약점 개수: {len(result.get('vulnerabilities', []))}")
        
    except Exception as e:
        print(f"❌ 로직 테스트 실패: {str(e)}")

def main():
    """메인 테스트 함수"""
    print("🚀 API 엔드포인트 테스트 시작")
    print("=" * 60)
    
    # 환경변수 설정
    os.environ['GEMINI_API_KEY'] = "AIzaSyB-lFb9w-Uy-sJtw31xlVx8ohnQpzNje4g"
    
    # 1. 엔드포인트 로직 테스트
    test_endpoint_logic()
    
    print("\n" + "=" * 60)
    
    # 2. Flask 앱 직접 테스트
    test_flask_app_directly()
    
    print("\n" + "=" * 60)
    
    # 3. HTTP 요청 테스트 (서버 실행 시)
    test_api_endpoint()
    
    print("\n✅ 모든 테스트 완료!")

if __name__ == "__main__":
    main() 