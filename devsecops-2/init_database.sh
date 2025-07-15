#!/bin/bash

# RDS 연결 정보
RDS_HOST="flask-db.czos9xo3nzg2.ap-northeast-2.rds.amazonaws.com"
RDS_USER="admin"
RDS_PASSWORD="yourstrongpassword"
RDS_DATABASE="saju"

echo "데이터베이스 초기화를 시작합니다..."

# MySQL 클라이언트 설치 (Ubuntu)
sudo apt update
sudo apt install -y mysql-client

# 데이터베이스 초기화
mysql -h $RDS_HOST -u $RDS_USER -p$RDS_PASSWORD << EOF
CREATE DATABASE IF NOT EXISTS $RDS_DATABASE;
USE $RDS_DATABASE;

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    birth VARCHAR(20),
    hour VARCHAR(10),
    result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

SHOW TABLES;
DESCRIBE logs;
EOF

echo "데이터베이스 초기화가 완료되었습니다." 