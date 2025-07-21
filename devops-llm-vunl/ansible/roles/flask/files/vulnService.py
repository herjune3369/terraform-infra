import os
import json
import uuid
import pymysql
from datetime import datetime
from typing import List, Dict, Optional
from dotenv import load_dotenv
from llm_client import LLMClient
from report_generator import generate_final_report

# 환경변수 로딩
load_dotenv()

class VulnService:
    """취약점 분석 서비스 클래스"""
    
    def __init__(self):
        self.rds_host = os.getenv("RDS_HOST")
        self.rds_user = os.getenv("RDS_USER", "admin")
        self.rds_password = os.getenv("RDS_PASSWORD", "yourstrongpassword")
        self.rds_database = os.getenv("RDS_DATABASE", "saju")
        self.llm_client = LLMClient()
    
    def create_report(self, file) -> str:
        """
        취약점 분석 보고서 생성
        
        Args:
            file: 업로드된 이미지 파일 객체
            
        Returns:
            str: 생성된 report_id
            
        Raises:
            Exception: 분석 또는 DB 저장 실패 시
        """
        try:
            # 1. LLM을 사용하여 취약점 분석
            vuln_list = self._analyze_vuln_image(file)
            
            if not vuln_list:
                raise Exception("취약점 분석 결과가 없습니다.")
            
            # 2. 새로운 report_id 생성
            report_id = str(uuid.uuid4())
            
            # 3. 파일 저장
            filename = self._save_uploaded_file(file, report_id)
            
            # 4. DB에 각 취약점 정보 저장
            self._save_vuln_reports_to_db(report_id, vuln_list, filename)
            
            return report_id
            
        except Exception as e:
            raise Exception(f"보고서 생성 실패: {str(e)}")
    
    def _analyze_vuln_image(self, file) -> List[Dict]:
        """
        LLM을 사용하여 이미지에서 취약점 분석
        
        Args:
            file: 이미지 파일 객체
            
        Returns:
            List[Dict]: 취약점 분석 결과 배열
        """
        try:
            # LLMClient를 사용하여 이미지 분석
            vuln_list = self.llm_client.analyze_vuln_image(file)
            
            if not vuln_list:
                raise Exception("LLM 분석 결과가 없습니다.")
            
            return vuln_list
            
        except Exception as e:
            raise Exception(f"이미지 분석 실패: {str(e)}")
    
    def _save_uploaded_file(self, file, report_id: str) -> str:
        """
        업로드된 파일을 저장
        
        Args:
            file: 업로드된 파일 객체
            report_id: 보고서 ID
            
        Returns:
            str: 저장된 파일명
        """
        try:
            from werkzeug.utils import secure_filename
            
            # 업로드 폴더 생성
            upload_folder = 'uploads'
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            # 파일명 생성
            original_filename = secure_filename(file.filename)
            file_extension = os.path.splitext(original_filename)[1]
            unique_filename = f"{report_id}{file_extension}"
            filepath = os.path.join(upload_folder, unique_filename)
            
            # 파일 저장
            file.save(filepath)
            
            return unique_filename
            
        except Exception as e:
            raise Exception(f"파일 저장 실패: {str(e)}")
    
    def _save_vuln_reports_to_db(self, report_id: str, vuln_list: List[Dict], filename: str):
        """
        취약점 분석 결과를 DB에 저장
        
        Args:
            report_id: 보고서 ID
            vuln_list: 취약점 분석 결과 배열
            filename: 저장된 이미지 파일명
        """
        try:
            conn = pymysql.connect(
                host=self.rds_host,
                user=self.rds_user,
                password=self.rds_password,
                database=self.rds_database
            )
            
            with conn.cursor() as cursor:
                for item in vuln_list:
                    # 각 취약점을 개별 레코드로 저장
                    cursor.execute("""
                        INSERT INTO vuln_reports 
                        (report_id, vuln_id, type, incidents, risk, management, metacognition, image_filename, created_at) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        report_id,
                        item.get('id', 'VULN-UNKNOWN'),
                        item.get('type', 'Unknown'),
                        json.dumps(item.get('incidents', [])),
                        item.get('risk', ''),
                        json.dumps(item.get('management', {})),
                        item.get('metacognition', ''),
                        filename,
                        datetime.now()
                    ))
                
                conn.commit()
            
            conn.close()
            
        except Exception as e:
            raise Exception(f"DB 저장 실패: {str(e)}")
    
    def get_report(self, report_id: str) -> Optional[Dict]:
        """
        보고서 조회
        
        Args:
            report_id: 보고서 ID
            
        Returns:
            Optional[Dict]: 보고서 정보 또는 None
        """
        try:
            conn = pymysql.connect(
                host=self.rds_host,
                user=self.rds_user,
                password=self.rds_password,
                database=self.rds_database
            )
            
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT report_id, vuln_id, type, incidents, risk, management, metacognition, image_filename, created_at
                    FROM vuln_reports 
                    WHERE report_id = %s
                    ORDER BY created_at
                """, (report_id,))
                
                rows = cursor.fetchall()
            
            conn.close()
            
            if not rows:
                return None
            
            # 결과를 구조화된 형태로 변환
            report_data = {
                "report_id": report_id,
                "image_filename": rows[0][7],  # image_filename
                "created_at": rows[0][8].isoformat() if rows[0][8] else None,  # created_at
                "vulnerabilities": []
            }
            
            for row in rows:
                vulnerability = {
                    "vuln_id": row[1],  # vuln_id
                    "type": row[2],     # type
                    "incidents": json.loads(row[3]) if row[3] else [],  # incidents
                    "risk": row[4],     # risk
                    "management": json.loads(row[5]) if row[5] else {},  # management
                    "metacognition": row[6]  # metacognition
                }
                report_data["vulnerabilities"].append(vulnerability)
            
            return report_data
            
        except Exception as e:
            raise Exception(f"보고서 조회 실패: {str(e)}")
    
    def list_reports(self, limit: int = 10) -> List[Dict]:
        """
        보고서 목록 조회
        
        Args:
            limit: 조회할 최대 개수
            
        Returns:
            List[Dict]: 보고서 목록
        """
        try:
            conn = pymysql.connect(
                host=self.rds_host,
                user=self.rds_user,
                password=self.rds_password,
                database=self.rds_database
            )
            
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT DISTINCT report_id, image_filename, created_at, COUNT(*) as vuln_count
                    FROM vuln_reports 
                    GROUP BY report_id, image_filename, created_at
                    ORDER BY created_at DESC
                    LIMIT %s
                """, (limit,))
                
                rows = cursor.fetchall()
            
            conn.close()
            
            reports = []
            for row in rows:
                report = {
                    "report_id": row[0],
                    "image_filename": row[1],
                    "created_at": row[2].isoformat() if row[2] else None,
                    "vulnerability_count": row[3]
                }
                reports.append(report)
            
            return reports
            
        except Exception as e:
            raise Exception(f"보고서 목록 조회 실패: {str(e)}")
    
    def delete_report(self, report_id: str) -> bool:
        """
        보고서 삭제
        
        Args:
            report_id: 보고서 ID
            
        Returns:
            bool: 삭제 성공 여부
        """
        try:
            conn = pymysql.connect(
                host=self.rds_host,
                user=self.rds_user,
                password=self.rds_password,
                database=self.rds_database
            )
            
            with conn.cursor() as cursor:
                # 관련 이미지 파일명 조회
                cursor.execute("""
                    SELECT DISTINCT image_filename FROM vuln_reports 
                    WHERE report_id = %s
                """, (report_id,))
                
                image_files = cursor.fetchall()
                
                # DB에서 레코드 삭제
                cursor.execute("DELETE FROM vuln_reports WHERE report_id = %s", (report_id,))
                conn.commit()
            
            conn.close()
            
            # 이미지 파일 삭제
            for (image_filename,) in image_files:
                if image_filename:
                    file_path = os.path.join('uploads', image_filename)
                    if os.path.exists(file_path):
                        os.remove(file_path)
            
            return True
            
        except Exception as e:
            raise Exception(f"보고서 삭제 실패: {str(e)}")
    
    def generate_final_report(self, report_id: str, target_system: str = "웹 애플리케이션") -> str:
        """
        최종 보안 취약점 준수 강화 리포트 생성
        
        Args:
            report_id: 보고서 ID
            target_system: 대상 시스템명
            
        Returns:
            str: Markdown 형식의 최종 보고서
            
        Raises:
            Exception: 보고서 생성 실패 시
        """
        try:
            # 1. DB에서 취약점 데이터 조회
            report_data = self.get_report(report_id)
            if not report_data:
                raise Exception("보고서를 찾을 수 없습니다.")
            
            vulnerabilities = report_data.get('vulnerabilities', [])
            if not vulnerabilities:
                raise Exception("취약점 데이터가 없습니다.")
            
            # 2. 이미지 파일명 조회
            image_filename = report_data.get('image_filename', 'unknown.jpg')
            
            # 3. 최종 보고서 생성
            final_report = generate_final_report(
                vuln_list=vulnerabilities,
                target_system=target_system,
                image_filename=image_filename
            )
            
            return final_report
            
        except Exception as e:
            raise Exception(f"최종 보고서 생성 실패: {str(e)}")


# 전역 인스턴스 생성
vuln_service = VulnService()


# 편의 함수들
def create_report(file) -> str:
    """보고서 생성 편의 함수"""
    return vuln_service.create_report(file)


def get_report(report_id: str) -> Optional[Dict]:
    """보고서 조회 편의 함수"""
    return vuln_service.get_report(report_id)


def list_reports(limit: int = 10) -> List[Dict]:
    """보고서 목록 조회 편의 함수"""
    return vuln_service.list_reports(limit)


def delete_report(report_id: str) -> bool:
    """보고서 삭제 편의 함수"""
    return vuln_service.delete_report(report_id)

def generate_final_report_md(report_id: str, target_system: str = "웹 애플리케이션") -> str:
    """최종 보고서 생성 편의 함수"""
    return vuln_service.generate_final_report(report_id, target_system) 