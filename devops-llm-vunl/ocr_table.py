# ocr_table.py

import cv2
import numpy as np
import pytesseract
from PIL import Image
import re
from typing import List, Dict, Any
import os


def parse_vuln_table(image_path: str) -> List[Dict[str, Any]]:
    """
    이미지 파일 경로를 받아, 화면에 보이는 표를 OCR로 인식하고
    각 행을 아래 형태의 딕셔너리로 파싱하여 리스트로 반환합니다.

    반환 형식:
    [
      {
        "type": str,         # '취약점 항목' 컬럼 값
        "summary": str,      # '상세 내용' 컬럼 전체 텍스트
        "first_found": int,  # '최초' 컬럼 값 (정수)
        "status": str        # '이행' 컬럼 값 (문자열)
      },
      ...
    ]
    """
    try:
        # 1) 이미지 로드 및 전처리
        image = preprocess_image(image_path)
        
        # 2) OCR 실행
        ocr_text = extract_text_from_image(image)
        
        # 3) 표 데이터 파싱
        table_data = parse_table_from_text(ocr_text)
        
        return table_data
        
    except Exception as e:
        print(f"OCR 파싱 실패: {e}")
        # 실패 시 기본 데이터 반환
        return [
            {
                "type": "Unknown",
                "summary": "OCR 분석 실패",
                "first_found": 1,
                "status": "Unknown"
            }
        ]


def preprocess_image(image_path: str) -> np.ndarray:
    """이미지 전처리: 노이즈 제거, 대비 향상"""
    # 이미지 로드
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError(f"이미지를 로드할 수 없습니다: {image_path}")
    
    # 그레이스케일 변환
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # 노이즈 제거
    denoised = cv2.medianBlur(gray, 3)
    
    # 대비 향상
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
    enhanced = clahe.apply(denoised)
    
    # 이진화
    _, binary = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    
    return binary


def extract_text_from_image(image: np.ndarray) -> str:
    """이미지에서 텍스트 추출"""
    # pytesseract 설정
    custom_config = r'--oem 3 --psm 6 -c tessedit_char_whitelist=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz가-힣\s\-\.\,\:\;\(\)\[\]\{\}\|\/\_'
    
    # OCR 실행
    text = pytesseract.image_to_string(image, config=custom_config, lang='kor+eng')
    
    return text


def parse_table_from_text(text: str) -> List[Dict[str, Any]]:
    """OCR 텍스트에서 표 데이터 파싱"""
    lines = text.strip().split('\n')
    table_data = []
    
    # 헤더 패턴 (다양한 형태 지원)
    header_patterns = [
        r'취약점\s*항목.*상세\s*내용.*최초.*이행',
        r'취약점.*내용.*최초.*이행',
        r'항목.*내용.*최초.*이행',
        r'Type.*Summary.*First.*Status',
        r'Vulnerability.*Description.*First.*Status'
    ]
    
    # 헤더 라인 찾기
    header_line_idx = -1
    for i, line in enumerate(lines):
        for pattern in header_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                header_line_idx = i
                break
        if header_line_idx != -1:
            break
    
    if header_line_idx == -1:
        # 헤더를 찾지 못한 경우, 첫 번째 라인을 헤더로 가정
        header_line_idx = 0
    
    # 데이터 라인 파싱
    for i in range(header_line_idx + 1, len(lines)):
        line = lines[i].strip()
        if not line or len(line) < 5:  # 빈 라인 또는 너무 짧은 라인 스킵
            continue
            
        # 라인 파싱
        row_data = parse_table_row(line)
        if row_data:
            table_data.append(row_data)
    
    return table_data


def parse_table_row(line: str) -> Dict[str, Any]:
    """개별 테이블 행 파싱"""
    try:
        # 탭이나 여러 공백으로 분리
        parts = re.split(r'\t+|\s{3,}', line.strip())
        
        if len(parts) < 3:  # 최소 3개 컬럼 필요
            return None
        
        # 컬럼 추출 및 정리
        type_col = parts[0].strip() if len(parts) > 0 else "Unknown"
        
        # summary는 나머지 컬럼들을 합쳐서 구성
        summary_parts = parts[1:-2] if len(parts) > 3 else [parts[1]] if len(parts) > 1 else []
        summary = ' '.join(summary_parts).strip()
        
        # first_found 파싱
        first_found_str = parts[-2].strip() if len(parts) > 2 else "1"
        first_found = extract_number(first_found_str)
        
        # status 파싱
        status = parts[-1].strip() if len(parts) > 1 else "Unknown"
        
        return {
            "type": type_col,
            "summary": summary,
            "first_found": first_found,
            "status": status
        }
        
    except Exception as e:
        print(f"행 파싱 실패: {line} - {e}")
        return None


def extract_number(text: str) -> int:
    """텍스트에서 숫자 추출"""
    try:
        # 숫자만 추출
        numbers = re.findall(r'\d+', text)
        if numbers:
            return int(numbers[0])
        return 1  # 기본값
    except:
        return 1


def validate_table_data(table_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """테이블 데이터 검증 및 정리"""
    validated_data = []
    
    for row in table_data:
        if not row:
            continue
            
        # 필수 필드 검증
        if not row.get('type') or row['type'] == 'Unknown':
            continue
            
        # 기본값 설정
        validated_row = {
            "type": row.get('type', 'Unknown'),
            "summary": row.get('summary', ''),
            "first_found": row.get('first_found', 1),
            "status": row.get('status', 'Unknown')
        }
        
        validated_data.append(validated_row)
    
    return validated_data


# 테스트 함수
def test_ocr_parsing():
    """OCR 파싱 테스트"""
    test_image_path = "test_vuln_image.png"
    
    if os.path.exists(test_image_path):
        print("OCR 테스트 시작...")
        result = parse_vuln_table(test_image_path)
        print(f"파싱된 행 수: {len(result)}")
        for i, row in enumerate(result):
            print(f"행 {i+1}: {row}")
    else:
        print(f"테스트 이미지가 없습니다: {test_image_path}")


if __name__ == "__main__":
    test_ocr_parsing() 