#!/usr/bin/env python3
"""
VulnService 테스트 스크립트
"""

import os
import sys
import json
import asyncio

# Flask 앱 디렉토리를 Python 경로에 추가
sys.path.append('ansible/roles/flask/files')

from vulnService import VulnService, create_report, get_report, list_reports, delete_report

def create_test_image():
    """테스트용 이미지 생성"""
    try:
        from PIL import Image, ImageDraw, ImageFont
        
        # 간단한 취약점 진단 결과 이미지 생성
        img = Image.new('RGB', (800, 600), color='white')
        draw = ImageDraw.Draw(img)
        
        # 기본 폰트 사용
        try:
            font = ImageFont.truetype("arial.ttf", 16)
        except:
            font = ImageFont.load_default()
        
        text = """Web Vulnerability Scan Result

Vulnerability ID: VULN-001
Type: SQL Injection
Severity: HIGH
Location: /login.php

Details:
- Insufficient input validation
- No Prepared Statement usage
- Database error information exposure

Recommendations:
1. Strengthen input validation
2. Use Prepared Statements
3. Hide error messages"""
        
        draw.text((50, 50), text, fill='black', font=font)
        
        test_image_path = "test_vuln_image.png"
        img.save(test_image_path)
        print(f"✅ 테스트 이미지 생성: {test_image_path}")
        return test_image_path
        
    except ImportError:
        print("❌ PIL 라이브러리가 설치되지 않았습니다.")
        return None
    except Exception as e:
        print(f"❌ 테스트 이미지 생성 실패: {str(e)}")
        return None

class MockFile:
    """테스트용 파일 객체"""
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
    
    def save(self, path):
        import shutil
        shutil.copy2(self.filepath, path)
    
    def read(self):
        with open(self.filepath, 'rb') as f:
            return f.read()
    
    def seek(self, pos):
        pass

async def test_create_report():
    """보고서 생성 테스트"""
    print("🔍 보고서 생성 테스트...")
    
    try:
        # 테스트 이미지 생성
        test_image = create_test_image()
        if not test_image:
            return False
        
        # Mock 파일 객체 생성
        mock_file = MockFile(test_image)
        
        # 보고서 생성
        report_id = await create_report(mock_file)
        
        print(f"✅ 보고서 생성 성공: {report_id}")
        
        # 생성된 보고서 조회
        report_data = get_report(report_id)
        if report_data:
            print("✅ 보고서 조회 성공")
            print(f"📊 취약점 개수: {len(report_data.get('vulnerabilities', []))}")
        else:
            print("❌ 보고서 조회 실패")
            return False
        
        # 보고서 목록 조회
        reports = list_reports(5)
        print(f"✅ 보고서 목록 조회 성공: {len(reports)}개")
        
        # 테스트 보고서 삭제
        success = delete_report(report_id)
        if success:
            print("✅ 보고서 삭제 성공")
        else:
            print("❌ 보고서 삭제 실패")
        
        # 정리
        if os.path.exists(test_image):
            os.remove(test_image)
            print(f"🧹 테스트 이미지 삭제: {test_image}")
        
        return True
        
    except Exception as e:
        print(f"❌ 보고서 생성 테스트 실패: {str(e)}")
        return False

def test_vuln_service_class():
    """VulnService 클래스 테스트"""
    print("🔍 VulnService 클래스 테스트...")
    
    try:
        # 서비스 인스턴스 생성
        service = VulnService()
        print("✅ VulnService 인스턴스 생성 성공")
        
        # 환경변수 확인
        print(f"📋 RDS_HOST: {service.rds_host}")
        print(f"📋 RDS_DATABASE: {service.rds_database}")
        
        return True
        
    except Exception as e:
        print(f"❌ VulnService 클래스 테스트 실패: {str(e)}")
        return False

async def main():
    """메인 테스트 함수"""
    print("🚀 VulnService 테스트 시작")
    print("=" * 50)
    
    # 환경변수 설정
    os.environ['GEMINI_API_KEY'] = "AIzaSyB-lFb9w-Uy-sJtw31xlVx8ohnQpzNje4g"
    
    # 1. VulnService 클래스 테스트
    if not test_vuln_service_class():
        print("❌ 클래스 테스트 실패")
        return
    
    print()
    
    # 2. 보고서 생성 테스트
    if await test_create_report():
        print("✅ 모든 테스트 통과!")
    else:
        print("❌ 보고서 생성 테스트 실패")

if __name__ == "__main__":
    asyncio.run(main()) 