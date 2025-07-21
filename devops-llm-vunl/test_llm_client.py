#!/usr/bin/env python3
"""
LLMClient 테스트 스크립트
"""

import os
import json
import sys

# Flask 앱 디렉토리를 Python 경로에 추가
sys.path.append('ansible/roles/flask/files')
from llm_client import LLMClient

def test_llm_connection():
    """LLM API 연결 테스트"""
    print("🔍 LLM API 연결 테스트 중...")
    
    try:
        client = LLMClient()
        if client.test_connection():
            print("✅ LLM API 연결 성공")
            return True
        else:
            print("❌ LLM API 연결 실패")
            return False
    except Exception as e:
        print(f"❌ LLM API 연결 오류: {str(e)}")
        return False

def test_image_analysis(image_path):
    """이미지 분석 테스트"""
    print(f"🔍 이미지 분석 테스트: {image_path}")
    
    if not os.path.exists(image_path):
        print(f"❌ 이미지 파일을 찾을 수 없습니다: {image_path}")
        return False
    
    try:
        client = LLMClient()
        
        with open(image_path, 'rb') as f:
            results = client.analyze_vuln_image(f, image_path)
        
        print("✅ 이미지 분석 성공")
        print("📊 분석 결과:")
        print(json.dumps(results, indent=2, ensure_ascii=False))
        
        return True
        
    except Exception as e:
        print(f"❌ 이미지 분석 실패: {str(e)}")
        return False

def create_sample_image():
    """테스트용 샘플 이미지 생성 (텍스트 기반)"""
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
        
        sample_path = "sample_vuln_image.png"
        img.save(sample_path)
        print(f"✅ 샘플 이미지 생성: {sample_path}")
        return sample_path
        
    except ImportError:
        print("❌ PIL 라이브러리가 설치되지 않았습니다.")
        print("pip install Pillow로 설치하세요.")
        return None
    except Exception as e:
        print(f"❌ 샘플 이미지 생성 실패: {str(e)}")
        return None

def main():
    """메인 테스트 함수"""
    print("🚀 LLMClient 테스트 시작")
    print("=" * 50)
    
    # 1. 연결 테스트
    if not test_llm_connection():
        print("❌ 연결 테스트 실패. 환경변수를 확인하세요.")
        return
    
    print()
    
    # 2. 샘플 이미지 생성
    sample_image = create_sample_image()
    if not sample_image:
        print("❌ 샘플 이미지 생성 실패")
        return
    
    print()
    
    # 3. 이미지 분석 테스트
    if test_image_analysis(sample_image):
        print("✅ 모든 테스트 통과!")
    else:
        print("❌ 이미지 분석 테스트 실패")
    
    # 4. 정리
    if os.path.exists(sample_image):
        os.remove(sample_image)
        print(f"🧹 임시 파일 삭제: {sample_image}")

if __name__ == "__main__":
    main() 