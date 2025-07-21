CREATE DATABASE IF NOT EXISTS saju;
USE saju;

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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_report_id (report_id),
    INDEX idx_vuln_id (vuln_id),
    INDEX idx_created_at (created_at),
    INDEX idx_type (type)
); 