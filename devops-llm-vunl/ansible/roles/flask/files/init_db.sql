CREATE DATABASE IF NOT EXISTS flask_app;
USE flask_app;

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    birth VARCHAR(20),
    hour VARCHAR(10),
    result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 취약점 분석 보고서 테이블
CREATE TABLE IF NOT EXISTS vuln_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    report_id VARCHAR(36) NOT NULL,
    vuln_id VARCHAR(50) NOT NULL,
    type VARCHAR(100) NOT NULL,
    incidents JSON,
    risk TEXT,
    management JSON,
    metacognition TEXT,
    image_filename VARCHAR(255) NOT NULL,
    website_url VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_report_id (report_id),
    INDEX idx_vuln_id (vuln_id),
    INDEX idx_created_at (created_at),
    INDEX idx_type (type),
    INDEX idx_website_url (website_url)
);

-- 기존 테이블에 website_url 컬럼 추가 (이미 존재하는 경우 무시)
ALTER TABLE vuln_reports ADD COLUMN IF NOT EXISTS website_url VARCHAR(500);
ALTER TABLE vuln_reports ADD INDEX IF NOT EXISTS idx_website_url (website_url); 