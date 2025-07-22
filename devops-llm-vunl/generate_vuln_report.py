#!/usr/bin/env python3
"""
CLI 엔트리포인트: 진단 결과 이미지로부터 전체 취약점 종합 진단 보고서 생성

사용법:
    python generate_vuln_report.py <image_path> [--author AUTHOR] [--target-system TARGET_SYSTEM]

예시:
    python generate_vuln_report.py vuln_scan_result.png --author "보안진단팀" --target-system "웹 애플리케이션"
"""

import argparse
import sys
import os
import datetime
from typing import List, Dict

# OCR 모듈은 선택적으로 import
try:
    from ocr_table import parse_vuln_table
    OCR_AVAILABLE = True
except ImportError:
    print("Warning: OCR module not available, using mock data", file=sys.stderr)
    OCR_AVAILABLE = False

# LLM 클라이언트 import
try:
    from llm_client import enrich_vuln_details
    LLM_AVAILABLE = True
except ImportError:
    print("Warning: LLM client not available, using mock data", file=sys.stderr)
    LLM_AVAILABLE = False

# 리포트 포매터 import
try:
    from report_formatter import format_vuln_report
    FORMATTER_AVAILABLE = True
except ImportError:
    print("Warning: Report formatter not available", file=sys.stderr)
    FORMATTER_AVAILABLE = False


def get_mock_vuln_data() -> List[Dict]:
    """OCR이 없을 때 사용할 mock 데이터"""
    return [
        {
            "type": "SQL Injection",
            "summary": "로그인 페이지에서 SQL Injection 취약점 발견",
            "first_found": 5,
            "status": "Active",
            "module": "/login.php"
        },
        {
            "type": "XSS",
            "summary": "댓글 기능에서 Cross-Site Scripting 취약점 발견",
            "first_found": 3,
            "status": "Active",
            "module": "/comment.php"
        },
        {
            "type": "File Upload",
            "summary": "파일 업로드 기능에서 악성 파일 업로드 가능",
            "first_found": 4,
            "status": "Active",
            "module": "/upload.php"
        }
    ]








def format_vuln_report(vuln_list: List[Dict], metadata: Dict) -> str:
    """취약점 리스트를 Markdown 보고서로 포매팅"""
    try:
        if FORMATTER_AVAILABLE:
            # 새로운 ReportFormatter 사용
            from report_formatter import format_vuln_report as format_report
            return format_report(vuln_list, metadata)
        else:
            # Fallback: 간단한 보고서 생성
            report = f"""# 웹 취약점 진단 보고서

## 1. 보고서 개요

* **작성일**: {metadata.get('date', 'N/A')}
* **작성자/팀**: {metadata.get('author', '보안진단팀')}
* **대상 시스템**: {metadata.get('targetSystem', '웹 애플리케이션')}
* **분석 이미지**: {metadata.get('image_filename', 'unknown.jpg')}

---

## 2. 취약점 요약

| 취약점 ID | 유형 | 심각도 | 모듈 | 요약 |
|-----------|------|--------|------|------|
"""
            
            for vuln in vuln_list:
                report += f"| {vuln['id']} | {vuln['type']} | {vuln['severity']} | {vuln['module']} | {vuln['summary']} |\n"
            
            report += "\n---\n\n## 3. 취약점별 상세 분석\n\n"
            
            for vuln in vuln_list:
                report += f"### {vuln['id']} - {vuln['type']}\n\n"
                report += f"**위험성**\n{vuln['risk']}\n\n"
                report += f"**유사 해킹 사고 사례**\n"
                incident = vuln['incident']
                report += f"- **사례명**: {incident['name']}\n"
                report += f"- **발생일**: {incident['date']}\n"
                report += f"- **피해 요약**: {incident['summary']}\n\n"
                report += "---\n\n"
            
            report += "## 4. 종합 권고사항\n\n"
            report += "1. **즉시 대응**: 발견된 모든 취약점에 대한 즉시 패치 적용\n"
            report += "2. **보안 강화**: 정기적인 보안 점검 및 모니터링 체계 구축\n"
            report += "3. **교육 실시**: 개발자 및 운영자 대상 보안 교육 강화\n"
            report += "4. **정책 수립**: 보안 개발 생명주기(SDLC) 도입\n\n"
            
            report += "*End of Report*"
            
            return report
        
    except Exception as e:
        print(f"Error: Report formatting failed: {e}", file=sys.stderr)
        raise


def main():
    """메인 함수: CLI 파이프라인 실행"""
    try:
        # 1) argparse 설정
        parser = argparse.ArgumentParser(
            description="진단 결과 이미지로부터 전체 취약점 종합 진단 보고서 생성"
        )
        parser.add_argument("image_path", help="취약점 진단 결과 이미지 파일 경로")
        parser.add_argument(
            "--author", default="보안진단팀", help="보고서 작성자/팀 (기본: 보안진단팀)"
        )
        parser.add_argument(
            "--target-system",
            default="웹 애플리케이션 인증·업로드·관리 기능",
            help="대상 시스템명 (기본: 웹 애플리케이션 인증·업로드·관리 기능)"
        )
        args = parser.parse_args()

        # 2) 오늘 날짜 메타데이터 구성
        metadata = {
            "date": datetime.date.today().isoformat(),
            "author": args.author,
            "targetSystem": args.target_system,
            "image_filename": os.path.basename(args.image_path)
        }

        # 3) 이미지 파일 존재 확인
        try:
            with open(args.image_path, "rb") as f:
                f.read(1)  # 파일이 읽기 가능한지 확인
        except FileNotFoundError:
            print(f"Error: Image file not found: {args.image_path}", file=sys.stderr)
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied accessing file: {args.image_path}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: Unable to read image file: {e}", file=sys.stderr)
            sys.exit(1)

        # 4) OCR로 표 파싱
        print("🔍 이미지에서 취약점 테이블을 추출하는 중...", file=sys.stderr)
        try:
            if OCR_AVAILABLE:
                rows = parse_vuln_table(args.image_path)
            else:
                rows = get_mock_vuln_data()
        except Exception as e:
            print(f"Error: Unable to parse image: {e}", file=sys.stderr)
            sys.exit(1)

        # 5) 초기 vuln_list 구축
        print("📋 취약점 리스트를 구축하는 중...", file=sys.stderr)
        try:
            vuln_list = []
            for idx, row in enumerate(rows, start=1):
                # 필수 필드 검증
                if not isinstance(row, dict):
                    raise ValueError(f"Invalid row format at index {idx}")
                
                if "type" not in row or "summary" not in row:
                    raise ValueError(f"Missing required fields in row {idx}")
                
                vuln_list.append({
                    "id": f"VULN-{idx:03d}",
                    "type": str(row["type"]),
                    "severity": "높음" if row.get("first_found", 0) >= 4 else "중간",
                    "module": str(row.get("module", "(unknown)")),
                    "summary": str(row["summary"]),
                    "risk": "",                  # 6단계에서 채워질 예정
                    "incident": {                # 6단계에서 채워질 예정
                        "name": "",
                        "date": "",
                        "summary": ""
                    }
                })
        except Exception as e:
            print(f"Error: Failed to build vulnerability list: {e}", file=sys.stderr)
            sys.exit(1)

        # 6) LLM 상세 보강
        print("🤖 LLM을 통한 상세 정보 보강 중...", file=sys.stderr)
        try:
            if LLM_AVAILABLE:
                vuln_list = enrich_vuln_details(vuln_list)
            else:
                # LLM이 없을 때 기본값 설정
                for vuln in vuln_list:
                    vuln['risk'] = f"{vuln['type']} 취약점은 심각한 보안 위험을 초래할 수 있습니다."
                    vuln['incident'] = {
                        "name": f"{vuln['type']} 관련 사고",
                        "date": "2024-01-01",
                        "summary": f"유사한 {vuln['type']} 취약점으로 인한 보안 사고가 발생했습니다."
                    }
        except Exception as e:
            print(f"Error: Unable to analyze vulnerabilities: {e}", file=sys.stderr)
            sys.exit(1)

        # 7) 보고서 포매팅
        print("📄 최종 보고서를 생성하는 중...", file=sys.stderr)
        try:
            markdown = format_vuln_report(vuln_list, metadata)
        except Exception as e:
            print(f"Error: Unable to generate report: {e}", file=sys.stderr)
            sys.exit(1)

        # 8) 정상 출력
        print(markdown)
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(130)  # SIGINT 종료 코드
    except SystemExit:
        raise  # argparse나 sys.exit() 호출을 그대로 전달
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main() 