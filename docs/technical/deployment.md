# Deployment Guide

Comprehensive guide for deploying BSN Knowledge in production environments, including infrastructure setup, security configuration, monitoring, and maintenance procedures.

## Overview

BSN Knowledge is designed for deployment in healthcare education environments with stringent security, compliance, and reliability requirements. This guide covers deployment options from single-instance installations to highly available multi-region configurations.

### Deployment Architecture

```
                    Load Balancer (HAProxy/NGINX)
                              ├─────────────────┤
                    API Gateway (FastAPI)        API Gateway (FastAPI)
                              ├─────────────────┤
                    Application Services         Application Services
                    ┌─────────┬─────────┐       ┌─────────┬─────────┐
                    │ Content │Analytics│       │ Content │Analytics│
                    │ Service │ Service │       │ Service │ Service │
                    └─────────┴─────────┘       └─────────┴─────────┘
                              ├─────────────────┤
                         Database Cluster (PostgreSQL)
                         ┌─────────┬─────────┬─────────┐
                         │ Primary │Replica 1│Replica 2│
                         └─────────┴─────────┴─────────┘
                              ├─────────────────┤
                         External Services
                         ┌─────────┬─────────┬─────────┐
                         │RAGnostic│OpenAI   │ Vector  │
                         │   AI    │   API   │   DB    │
                         └─────────┴─────────┴─────────┘
```

### Supported Deployment Environments

- **Cloud Platforms**: AWS, Azure, Google Cloud Platform
- **Container Orchestration**: Docker, Kubernetes, Docker Swarm
- **Traditional Infrastructure**: On-premises servers, virtual machines
- **Hybrid Deployments**: Cloud-bursting, multi-cloud configurations

## Prerequisites

### System Requirements

#### Minimum Configuration (Development/Testing)
```
CPU: 4 vCPUs
Memory: 8 GB RAM
Storage: 100 GB SSD
Network: 1 Gbps connection
OS: Ubuntu 20.04 LTS, RHEL 8, or CentOS 8
```

#### Recommended Production Configuration
```
CPU: 8 vCPUs (16+ for high-load institutions)
Memory: 32 GB RAM (64+ GB for large institutions)
Storage: 500 GB SSD (NVMe preferred)
Network: 10 Gbps connection
OS: Ubuntu 22.04 LTS or RHEL 9
Backup Storage: 2TB+ for data retention
```

#### High Availability Configuration
```
Load Balancer: 2 instances (active-passive)
Application Servers: 3+ instances (active-active)
Database: 1 primary + 2+ replicas
Storage: Distributed storage system (Ceph, GlusterFS)
Network: Redundant network connections
```

### Software Dependencies

#### Required Software Stack
```bash
# Python Runtime
Python 3.11+ (recommended 3.12)
pip 23.0+
virtualenv or similar

# Database Systems
PostgreSQL 15+ (primary database)
Redis 7.0+ (caching and session management)

# Web Server
NGINX 1.20+ (reverse proxy and static files)
or
Apache HTTP Server 2.4+

# Process Management
systemd (Linux service management)
supervisor (Python process management)

# Monitoring
Prometheus + Grafana (recommended)
ELK Stack (logging)

# Security
SSL/TLS certificates (Let's Encrypt or commercial)
Fail2ban (intrusion prevention)
UFW or iptables (firewall)
```

#### Optional but Recommended
```bash
# Container Platform
Docker 24.0+
Kubernetes 1.28+ (for container orchestration)

# Load Balancing
HAProxy 2.4+
NGINX Plus (commercial features)

# Backup Solutions
PostgreSQL WAL-E or pgBackRest
Restic (file system backups)

# Monitoring Extensions
New Relic, DataDog, or similar APM
PagerDuty (alerting)
```

## Installation

### Docker Deployment (Recommended)

#### Docker Compose Configuration

```yaml
# docker-compose.production.yml
version: '3.8'

services:
  bsn-knowledge-app:
    image: bsn-knowledge:latest
    container_name: bsn-knowledge-app
    restart: unless-stopped
    environment:
      - DATABASE_URL=postgresql://bsn_user:${DB_PASSWORD}@postgres:5432/bsn_knowledge
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=${SECRET_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - RAGNOSTIC_API_URL=https://ragnostic.internal.edu/api/v1
      - ENVIRONMENT=production
      - LOG_LEVEL=INFO
    ports:
      - "8000:8000"
    depends_on:
      - postgres
      - redis
    volumes:
      - ./logs:/app/logs
      - ./uploads:/app/uploads
    networks:
      - bsn-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  postgres:
    image: postgres:15
    container_name: bsn-postgres
    restart: unless-stopped
    environment:
      - POSTGRES_DB=bsn_knowledge
      - POSTGRES_USER=bsn_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_INITDB_ARGS=--encoding=UTF-8 --lc-collate=en_US.UTF-8 --lc-ctype=en_US.UTF-8
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init-db.sql
      - ./backups:/backups
    networks:
      - bsn-network
    command: >
      postgres
      -c shared_preload_libraries=pg_stat_statements
      -c pg_stat_statements.track=all
      -c max_connections=200
      -c shared_buffers=256MB
      -c effective_cache_size=1GB
      -c work_mem=4MB
      -c maintenance_work_mem=64MB

  redis:
    image: redis:7-alpine
    container_name: bsn-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
      - ./redis.conf:/usr/local/etc/redis/redis.conf
    networks:
      - bsn-network
    command: redis-server /usr/local/etc/redis/redis.conf

  nginx:
    image: nginx:alpine
    container_name: bsn-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
      - ./static:/var/www/static
    depends_on:
      - bsn-knowledge-app
    networks:
      - bsn-network

  prometheus:
    image: prom/prometheus:latest
    container_name: bsn-prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    networks:
      - bsn-network

  grafana:
    image: grafana/grafana:latest
    container_name: bsn-grafana
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/datasources:/etc/grafana/provisioning/datasources
    networks:
      - bsn-network

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:

networks:
  bsn-network:
    driver: bridge
```

#### Environment Configuration

```bash
# .env.production
# Database Configuration
DB_PASSWORD=your_secure_database_password
DATABASE_URL=postgresql://bsn_user:${DB_PASSWORD}@postgres:5432/bsn_knowledge

# Application Configuration
SECRET_KEY=your_secure_secret_key_at_least_32_characters_long
ENVIRONMENT=production
DEBUG=False
LOG_LEVEL=INFO

# External Services
OPENAI_API_KEY=your_openai_api_key
RAGNOSTIC_API_URL=https://ragnostic.internal.edu/api/v1
RAGNOSTIC_API_KEY=your_ragnostic_api_key

# Security Configuration
ALLOWED_HOSTS=bsn-knowledge.university.edu,api.bsn-knowledge.university.edu
CORS_ALLOWED_ORIGINS=https://lms.university.edu,https://portal.university.edu

# Session and Authentication
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=8

# Rate Limiting
RATE_LIMIT_GENERAL=1000
RATE_LIMIT_CONTENT_GENERATION=50
RATE_LIMIT_ASSESSMENT=200

# Monitoring
PROMETHEUS_ENABLED=True
GRAFANA_PASSWORD=your_grafana_admin_password

# Backup Configuration
BACKUP_RETENTION_DAYS=30
BACKUP_S3_BUCKET=bsn-knowledge-backups
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
```

#### NGINX Configuration

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 50M;

    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_min_length 10240;
    gzip_proxied expired no-cache no-store private must-revalidate auth;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/x-javascript
        application/xml+rss
        application/javascript
        application/json;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=content:10m rate=2r/s;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # Security Headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    # Upstream Configuration
    upstream bsn_app {
        server bsn-knowledge-app:8000;
        keepalive 32;
    }

    # HTTP to HTTPS Redirect
    server {
        listen 80;
        server_name bsn-knowledge.university.edu api.bsn-knowledge.university.edu;
        return 301 https://$server_name$request_uri;
    }

    # Main HTTPS Server
    server {
        listen 443 ssl http2;
        server_name bsn-knowledge.university.edu api.bsn-knowledge.university.edu;

        # SSL Certificates
        ssl_certificate /etc/nginx/ssl/certificate.pem;
        ssl_certificate_key /etc/nginx/ssl/private_key.pem;

        # API Routes with Rate Limiting
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://bsn_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Timeouts
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # Content Generation Routes (Lower Rate Limit)
        location ~ ^/api/v1/(nclex|study-guide|clinical-support)/ {
            limit_req zone=content burst=5 nodelay;
            proxy_pass http://bsn_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Extended timeouts for AI content generation
            proxy_connect_timeout 120s;
            proxy_send_timeout 120s;
            proxy_read_timeout 120s;
        }

        # Static Files
        location /static/ {
            alias /var/www/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # Health Check
        location /health {
            proxy_pass http://bsn_app;
            access_log off;
        }

        # Documentation
        location /docs {
            proxy_pass http://bsn_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

### Kubernetes Deployment

#### Kubernetes Manifests

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: bsn-knowledge
  labels:
    name: bsn-knowledge

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bsn-knowledge-config
  namespace: bsn-knowledge
data:
  DATABASE_URL: "postgresql://bsn_user@postgres:5432/bsn_knowledge"
  REDIS_URL: "redis://redis:6379/0"
  ENVIRONMENT: "production"
  LOG_LEVEL: "INFO"
  ALLOWED_HOSTS: "bsn-knowledge.university.edu,api.bsn-knowledge.university.edu"

---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: bsn-knowledge-secrets
  namespace: bsn-knowledge
type: Opaque
data:
  SECRET_KEY: <base64-encoded-secret-key>
  DB_PASSWORD: <base64-encoded-db-password>
  OPENAI_API_KEY: <base64-encoded-openai-key>
  RAGNOSTIC_API_KEY: <base64-encoded-ragnostic-key>

---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bsn-knowledge-app
  namespace: bsn-knowledge
  labels:
    app: bsn-knowledge-app
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: bsn-knowledge-app
  template:
    metadata:
      labels:
        app: bsn-knowledge-app
    spec:
      containers:
      - name: bsn-knowledge
        image: bsn-knowledge:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: bsn-knowledge-config
        - secretRef:
            name: bsn-knowledge-secrets
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        volumeMounts:
        - name: logs
          mountPath: /app/logs
      volumes:
      - name: logs
        emptyDir: {}

---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: bsn-knowledge-service
  namespace: bsn-knowledge
spec:
  selector:
    app: bsn-knowledge-app
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8000
  type: ClusterIP

---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bsn-knowledge-ingress
  namespace: bsn-knowledge
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - bsn-knowledge.university.edu
    - api.bsn-knowledge.university.edu
    secretName: bsn-knowledge-tls
  rules:
  - host: bsn-knowledge.university.edu
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: bsn-knowledge-service
            port:
              number: 80
  - host: api.bsn-knowledge.university.edu
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: bsn-knowledge-service
            port:
              number: 80

---
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: bsn-knowledge-hpa
  namespace: bsn-knowledge
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: bsn-knowledge-app
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Traditional Server Deployment

#### System Service Configuration

```bash
# /etc/systemd/system/bsn-knowledge.service
[Unit]
Description=BSN Knowledge API Server
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=exec
User=bsn-knowledge
Group=bsn-knowledge
WorkingDirectory=/opt/bsn-knowledge
Environment=PATH=/opt/bsn-knowledge/venv/bin
ExecStart=/opt/bsn-knowledge/venv/bin/python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 4
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always
RestartSec=10

# Security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/bsn-knowledge/logs /opt/bsn-knowledge/uploads

# Resource Limits
LimitNOFILE=65536
MemoryMax=4G

[Install]
WantedBy=multi-user.target
```

#### Installation Script

```bash
#!/bin/bash
# install-bsn-knowledge.sh

set -e

# Configuration
BSN_USER="bsn-knowledge"
BSN_HOME="/opt/bsn-knowledge"
PYTHON_VERSION="3.12"

# Create user and directories
sudo useradd -r -s /bin/bash -d $BSN_HOME -m $BSN_USER
sudo mkdir -p $BSN_HOME/{logs,uploads,backups}
sudo chown -R $BSN_USER:$BSN_USER $BSN_HOME

# Install system dependencies
sudo apt-get update
sudo apt-get install -y \
    python3.$PYTHON_VERSION \
    python3.$PYTHON_VERSION-venv \
    python3-pip \
    postgresql-client \
    redis-tools \
    nginx \
    curl \
    wget \
    unzip

# Create Python virtual environment
sudo -u $BSN_USER python3.$PYTHON_VERSION -m venv $BSN_HOME/venv

# Install Python dependencies
sudo -u $BSN_USER $BSN_HOME/venv/bin/pip install --upgrade pip
sudo -u $BSN_USER $BSN_HOME/venv/bin/pip install -r requirements.txt

# Copy application files
sudo cp -r src/ $BSN_HOME/
sudo cp -r scripts/ $BSN_HOME/
sudo cp requirements.txt $BSN_HOME/
sudo chown -R $BSN_USER:$BSN_USER $BSN_HOME/

# Install systemd service
sudo cp bsn-knowledge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable bsn-knowledge

# Configure NGINX
sudo cp nginx-site.conf /etc/nginx/sites-available/bsn-knowledge
sudo ln -sf /etc/nginx/sites-available/bsn-knowledge /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Configure firewall
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# Start services
sudo systemctl start bsn-knowledge
sudo systemctl status bsn-knowledge

echo "BSN Knowledge installation completed!"
echo "Access the application at: https://your-domain.edu"
echo "Check logs: journalctl -u bsn-knowledge -f"
```

## Database Setup and Migration

### PostgreSQL Configuration

#### Database Initialization

```sql
-- init-production-db.sql

-- Create database and user
CREATE DATABASE bsn_knowledge;
CREATE USER bsn_user WITH ENCRYPTED PASSWORD 'your_secure_password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE bsn_knowledge TO bsn_user;
ALTER USER bsn_user CREATEDB;

-- Connect to the database
\c bsn_knowledge

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "citext";

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO bsn_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO bsn_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO bsn_user;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO bsn_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO bsn_user;
```

#### Database Migration Script

```python
# scripts/migrate_database.py

import os
import asyncio
import asyncpg
from pathlib import Path

async def run_migration():
    """Run database migration for BSN Knowledge."""

    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        raise ValueError("DATABASE_URL environment variable not set")

    conn = await asyncpg.connect(database_url)

    try:
        # Read and execute migration scripts
        migration_dir = Path('scripts/migrations')
        migration_files = sorted(migration_dir.glob('*.sql'))

        for migration_file in migration_files:
            print(f"Running migration: {migration_file.name}")

            migration_sql = migration_file.read_text()
            await conn.execute(migration_sql)

            print(f"Completed migration: {migration_file.name}")

        print("All migrations completed successfully!")

    finally:
        await conn.close()

if __name__ == "__main__":
    asyncio.run(run_migration())
```

#### Performance Tuning

```bash
# PostgreSQL performance configuration
# Add to postgresql.conf

# Memory Configuration
shared_buffers = 256MB                  # 25% of RAM for smaller instances
effective_cache_size = 1GB              # 75% of RAM
work_mem = 4MB                          # Per-operation memory
maintenance_work_mem = 64MB             # Maintenance operations

# Connection Configuration
max_connections = 200                   # Adjust based on application needs
superuser_reserved_connections = 3

# WAL Configuration
wal_level = replica                     # Enable replication
max_wal_size = 1GB
min_wal_size = 80MB
checkpoint_completion_target = 0.7

# Query Performance
random_page_cost = 1.1                  # SSD-optimized
effective_io_concurrency = 200          # SSD-optimized
default_statistics_target = 100

# Logging
log_destination = 'stderr,csvlog'
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_statement = 'mod'                   # Log all DDL and DML
log_min_duration_statement = 1000       # Log slow queries (1s+)

# Monitoring
shared_preload_libraries = 'pg_stat_statements'
track_activity_query_size = 2048
```

### Database Backup and Recovery

#### Automated Backup Script

```bash
#!/bin/bash
# scripts/backup-database.sh

set -e

# Configuration
DB_NAME="bsn_knowledge"
DB_USER="bsn_user"
BACKUP_DIR="/opt/bsn-knowledge/backups"
RETENTION_DAYS=30
S3_BUCKET="bsn-knowledge-backups"

# Create backup directory
mkdir -p $BACKUP_DIR

# Generate backup filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/bsn_knowledge_$TIMESTAMP.sql"

# Create database backup
echo "Creating database backup..."
pg_dump -h localhost -U $DB_USER -d $DB_NAME -f $BACKUP_FILE

# Compress backup
gzip $BACKUP_FILE
BACKUP_FILE="$BACKUP_FILE.gz"

# Upload to S3 (if configured)
if [ ! -z "$S3_BUCKET" ]; then
    echo "Uploading backup to S3..."
    aws s3 cp $BACKUP_FILE s3://$S3_BUCKET/daily/
fi

# Clean up old backups
echo "Cleaning up old backups..."
find $BACKUP_DIR -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_FILE"
```

#### Recovery Procedures

```bash
#!/bin/bash
# scripts/restore-database.sh

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

BACKUP_FILE=$1
DB_NAME="bsn_knowledge"
DB_USER="bsn_user"

echo "WARNING: This will overwrite the existing database!"
read -p "Are you sure you want to continue? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Restore cancelled."
    exit 1
fi

# Stop application service
echo "Stopping BSN Knowledge service..."
sudo systemctl stop bsn-knowledge

# Drop and recreate database
echo "Recreating database..."
dropdb -h localhost -U $DB_USER $DB_NAME
createdb -h localhost -U $DB_USER $DB_NAME

# Restore from backup
echo "Restoring database from backup..."
if [[ $BACKUP_FILE == *.gz ]]; then
    gunzip -c $BACKUP_FILE | psql -h localhost -U $DB_USER -d $DB_NAME
else
    psql -h localhost -U $DB_USER -d $DB_NAME -f $BACKUP_FILE
fi

# Start application service
echo "Starting BSN Knowledge service..."
sudo systemctl start bsn-knowledge

echo "Database restore completed successfully!"
```

## Security Configuration

### SSL/TLS Configuration

#### Certificate Management

```bash
#!/bin/bash
# scripts/setup-ssl.sh

DOMAIN="bsn-knowledge.university.edu"
EMAIL="admin@university.edu"

# Install Certbot
sudo apt-get update
sudo apt-get install -y certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot certonly \
    --nginx \
    --email $EMAIL \
    --agree-tos \
    --no-eff-email \
    --domains $DOMAIN,api.$DOMAIN

# Set up automatic renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -

# Test renewal
sudo certbot renew --dry-run

echo "SSL certificates installed and auto-renewal configured!"
```

#### Security Headers Configuration

```nginx
# Security headers configuration (add to NGINX server block)

# HSTS (HTTP Strict Transport Security)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Content Security Policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src 'self' fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' api.openai.com;" always;

# X-Frame-Options
add_header X-Frame-Options "DENY" always;

# X-Content-Type-Options
add_header X-Content-Type-Options "nosniff" always;

# X-XSS-Protection
add_header X-XSS-Protection "1; mode=block" always;

# Referrer Policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Feature Policy
add_header Feature-Policy "geolocation 'none'; midi 'none'; camera 'none'; microphone 'none';" always;
```

### Firewall Configuration

```bash
#!/bin/bash
# scripts/setup-firewall.sh

# Reset UFW to defaults
sudo ufw --force reset

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (adjust port if needed)
sudo ufw allow 22/tcp

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow internal communication (adjust network as needed)
sudo ufw allow from 10.0.0.0/8 to any port 5432    # PostgreSQL
sudo ufw allow from 10.0.0.0/8 to any port 6379    # Redis

# Rate limiting for SSH
sudo ufw limit ssh

# Enable firewall
sudo ufw --force enable

# Show status
sudo ufw status verbose
```

### Intrusion Detection

```bash
# Install and configure Fail2Ban
sudo apt-get install -y fail2ban

# Create custom configuration
sudo tee /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = admin@university.edu
sender = fail2ban@university.edu

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-req-limit]
enabled = true
filter = nginx-req-limit
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10

[bsn-knowledge-api]
enabled = true
filter = bsn-knowledge-api
port = 8000
logpath = /opt/bsn-knowledge/logs/api.log
maxretry = 5
EOF

# Create custom filter for BSN Knowledge API
sudo tee /etc/fail2ban/filter.d/bsn-knowledge-api.conf << EOF
[Definition]
failregex = ^.*\[ERROR\].*Authentication failed.*<HOST>.*$
            ^.*\[ERROR\].*Rate limit exceeded.*<HOST>.*$
            ^.*\[ERROR\].*Invalid request.*<HOST>.*$
ignoreregex =
EOF

# Start and enable Fail2Ban
sudo systemctl start fail2ban
sudo systemctl enable fail2ban

echo "Fail2Ban configured and started!"
```

## Monitoring and Alerting

### Application Monitoring

#### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "bsn_knowledge_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'bsn-knowledge'
    static_configs:
      - targets: ['bsn-knowledge-app:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
```

#### Alert Rules

```yaml
# bsn_knowledge_rules.yml
groups:
- name: bsn_knowledge_alerts
  rules:

  # High Error Rate
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"

  # High Response Time
  - alert: HighResponseTime
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High response time detected"
      description: "95th percentile response time is {{ $value }} seconds"

  # Database Connection Issues
  - alert: DatabaseConnectionFailure
    expr: up{job="postgres"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Database connection failure"
      description: "PostgreSQL database is not responding"

  # Memory Usage
  - alert: HighMemoryUsage
    expr: (process_resident_memory_bytes / 1024 / 1024 / 1024) > 2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage"
      description: "Application memory usage is {{ $value }}GB"

  # Disk Space
  - alert: LowDiskSpace
    expr: (node_filesystem_free_bytes / node_filesystem_size_bytes) < 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Low disk space"
      description: "Disk usage is above 90% on {{ $labels.mountpoint }}"

  # NCLEX Generation Failures
  - alert: NCLEXGenerationFailure
    expr: rate(nclex_generation_failures_total[5m]) > 0.05
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "NCLEX generation failures detected"
      description: "NCLEX generation failure rate is {{ $value }} per second"
```

#### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "BSN Knowledge Monitoring",
    "panels": [
      {
        "title": "API Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[1m])",
            "legendFormat": "{{method}} {{path}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m])",
            "legendFormat": "5xx errors/sec"
          }
        ]
      },
      {
        "title": "Database Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "pg_stat_database_numbackends",
            "legendFormat": "Active connections"
          }
        ]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "process_resident_memory_bytes",
            "legendFormat": "Memory usage"
          }
        ]
      }
    ]
  }
}
```

### Log Management

#### Centralized Logging Configuration

```yaml
# docker-compose.logging.yml (add to main compose file)
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
    container_name: bsn-elasticsearch
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    networks:
      - bsn-network

  logstash:
    image: docker.elastic.co/logstash/logstash:8.8.0
    container_name: bsn-logstash
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logs:/logs
    ports:
      - "5044:5044"
    depends_on:
      - elasticsearch
    networks:
      - bsn-network

  kibana:
    image: docker.elastic.co/kibana/kibana:8.8.0
    container_name: bsn-kibana
    ports:
      - "5601:5601"
    environment:
      ELASTICSEARCH_HOSTS: http://elasticsearch:9200
    depends_on:
      - elasticsearch
    networks:
      - bsn-network

volumes:
  elasticsearch_data:
```

#### Logstash Pipeline Configuration

```ruby
# logstash/pipeline/logstash.conf
input {
  file {
    path => "/logs/*.log"
    start_position => "beginning"
    codec => json
  }

  beats {
    port => 5044
  }
}

filter {
  if [fields][service] == "bsn-knowledge" {
    # Parse BSN Knowledge application logs
    if [message] =~ /^\[.*\]/ {
      grok {
        match => {
          "message" => "^\[%{TIMESTAMP_ISO8601:timestamp}\] \[%{WORD:level}\] %{GREEDYDATA:log_message}"
        }
      }

      date {
        match => [ "timestamp", "yyyy-MM-dd HH:mm:ss,SSS" ]
      }
    }

    # Parse API request logs
    if [message] =~ /API Request/ {
      grok {
        match => {
          "message" => "API Request: %{WORD:method} %{URIPATH:path} - Status: %{NUMBER:status_code} - Duration: %{NUMBER:duration}ms"
        }
      }

      mutate {
        convert => {
          "status_code" => "integer"
          "duration" => "float"
        }
      }
    }
  }

  # Parse NGINX access logs
  if [fields][service] == "nginx" {
    grok {
      match => {
        "message" => "%{NGINXACCESS}"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "bsn-knowledge-%{+YYYY.MM.dd}"
  }

  # Output to stdout for debugging
  stdout {
    codec => rubydebug
  }
}
```

## Performance Optimization

### Application Performance

#### Caching Strategy

```python
# Enhanced caching configuration
import redis
from functools import wraps
import json
import hashlib

class BSNKnowledgeCache:
    def __init__(self, redis_url: str):
        self.redis_client = redis.from_url(redis_url, decode_responses=True)

    def cache_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate cache key from function arguments."""
        cache_data = {
            'args': args,
            'kwargs': sorted(kwargs.items())
        }
        cache_string = json.dumps(cache_data, sort_keys=True)
        cache_hash = hashlib.md5(cache_string.encode()).hexdigest()
        return f"{prefix}:{cache_hash}"

    def cached_response(self, ttl: int = 3600, prefix: str = "api"):
        """Decorator for caching API responses."""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Generate cache key
                cache_key = self.cache_key(prefix, *args, **kwargs)

                # Try to get from cache
                cached_result = self.redis_client.get(cache_key)
                if cached_result:
                    return json.loads(cached_result)

                # Execute function and cache result
                result = await func(*args, **kwargs)
                self.redis_client.setex(
                    cache_key,
                    ttl,
                    json.dumps(result, default=str)
                )

                return result
            return wrapper
        return decorator

# Usage in API endpoints
cache = BSNKnowledgeCache(redis_url="redis://localhost:6379/0")

@cache.cached_response(ttl=7200, prefix="nclex_questions")
async def generate_nclex_questions(topic: str, difficulty: str, count: int):
    """Cached NCLEX question generation."""
    # Implementation here
    pass

@cache.cached_response(ttl=1800, prefix="student_analytics")
async def get_student_analytics(student_id: str, time_period: str):
    """Cached student analytics."""
    # Implementation here
    pass
```

#### Database Optimization

```python
# Database connection pooling and optimization
import asyncpg
import asyncio
from contextlib import asynccontextmanager

class DatabaseManager:
    def __init__(self, database_url: str, min_size: int = 10, max_size: int = 100):
        self.database_url = database_url
        self.min_size = min_size
        self.max_size = max_size
        self.pool = None

    async def initialize(self):
        """Initialize connection pool."""
        self.pool = await asyncpg.create_pool(
            self.database_url,
            min_size=self.min_size,
            max_size=self.max_size,
            command_timeout=60,
            server_settings={
                'jit': 'off',  # Disable JIT for consistent performance
                'application_name': 'bsn_knowledge_api'
            }
        )

    @asynccontextmanager
    async def get_connection(self):
        """Get database connection from pool."""
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                yield connection

    async def execute_query(self, query: str, *args):
        """Execute query with connection pooling."""
        async with self.get_connection() as conn:
            return await conn.fetch(query, *args)

    async def close(self):
        """Close connection pool."""
        if self.pool:
            await self.pool.close()

# Optimized database queries
OPTIMIZED_QUERIES = {
    'student_competency_summary': '''
        SELECT
            sp.student_id,
            sp.overall_gpa,
            array_agg(
                json_build_object(
                    'domain', ca.aacn_domain,
                    'level', ca.proficiency_level,
                    'score', ca.score
                )
            ) as competencies
        FROM student_profiles sp
        JOIN competency_assessments ca ON sp.student_id = ca.student_id
        WHERE sp.student_id = $1
        GROUP BY sp.student_id, sp.overall_gpa
    ''',

    'batch_student_analytics': '''
        WITH student_metrics AS (
            SELECT
                student_id,
                COUNT(*) as total_activities,
                AVG(score) as avg_score,
                MAX(last_activity) as last_active
            FROM learning_activities
            WHERE student_id = ANY($1::text[])
            AND created_at >= $2
            GROUP BY student_id
        )
        SELECT * FROM student_metrics
        ORDER BY last_active DESC
    '''
}
```

### Load Testing

#### Performance Testing Script

```python
# scripts/load_test.py
import asyncio
import aiohttp
import time
import statistics
from dataclasses import dataclass
from typing import List
import json

@dataclass
class TestResult:
    endpoint: str
    method: str
    status_code: int
    response_time: float
    success: bool
    error: str = None

class LoadTester:
    def __init__(self, base_url: str, auth_token: str):
        self.base_url = base_url
        self.auth_token = auth_token
        self.results: List[TestResult] = []

    async def make_request(self, session: aiohttp.ClientSession, method: str, endpoint: str, data: dict = None) -> TestResult:
        """Make a single API request and measure performance."""

        headers = {"Authorization": f"Bearer {self.auth_token}"}
        url = f"{self.base_url}{endpoint}"

        start_time = time.time()

        try:
            async with session.request(method, url, json=data, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                await response.text()  # Consume response body
                response_time = time.time() - start_time

                return TestResult(
                    endpoint=endpoint,
                    method=method,
                    status_code=response.status,
                    response_time=response_time,
                    success=200 <= response.status < 400
                )

        except Exception as e:
            response_time = time.time() - start_time
            return TestResult(
                endpoint=endpoint,
                method=method,
                status_code=0,
                response_time=response_time,
                success=False,
                error=str(e)
            )

    async def test_endpoint(self, method: str, endpoint: str, data: dict, concurrent_requests: int, total_requests: int):
        """Test a single endpoint with concurrent requests."""

        connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
        async with aiohttp.ClientSession(connector=connector) as session:

            # Create semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(concurrent_requests)

            async def bounded_request():
                async with semaphore:
                    return await self.make_request(session, method, endpoint, data)

            # Execute requests
            tasks = [bounded_request() for _ in range(total_requests)]
            results = await asyncio.gather(*tasks)

            self.results.extend(results)
            return results

    def print_results(self):
        """Print test results summary."""

        if not self.results:
            print("No test results available")
            return

        # Group results by endpoint
        endpoints = {}
        for result in self.results:
            endpoint = result.endpoint
            if endpoint not in endpoints:
                endpoints[endpoint] = []
            endpoints[endpoint].append(result)

        print("\n" + "="*80)
        print("LOAD TEST RESULTS")
        print("="*80)

        for endpoint, results in endpoints.items():
            successful_results = [r for r in results if r.success]
            failed_results = [r for r in results if not r.success]

            print(f"\nEndpoint: {endpoint}")
            print(f"Total Requests: {len(results)}")
            print(f"Successful: {len(successful_results)} ({len(successful_results)/len(results)*100:.1f}%)")
            print(f"Failed: {len(failed_results)} ({len(failed_results)/len(results)*100:.1f}%)")

            if successful_results:
                response_times = [r.response_time for r in successful_results]
                print(f"Average Response Time: {statistics.mean(response_times):.3f}s")
                print(f"Median Response Time: {statistics.median(response_times):.3f}s")
                print(f"95th Percentile: {statistics.quantiles(response_times, n=20)[18]:.3f}s")
                print(f"Max Response Time: {max(response_times):.3f}s")

                # Check if performance meets requirements
                avg_time = statistics.mean(response_times)
                if "/nclex/" in endpoint or "/study-guide/" in endpoint:
                    threshold = 5.0  # 5 seconds for content generation
                else:
                    threshold = 0.5  # 500ms for other endpoints

                status = "✅ PASS" if avg_time <= threshold else "❌ FAIL"
                print(f"Performance Status: {status} (threshold: {threshold}s)")

            if failed_results:
                error_counts = {}
                for result in failed_results:
                    error = result.error or f"HTTP {result.status_code}"
                    error_counts[error] = error_counts.get(error, 0) + 1

                print("Error Details:")
                for error, count in error_counts.items():
                    print(f"  {error}: {count}")

async def run_load_test():
    """Execute comprehensive load test."""

    tester = LoadTester(
        base_url="https://api.bsn-knowledge.edu",
        auth_token="your_test_auth_token"
    )

    # Test scenarios
    test_scenarios = [
        {
            "name": "Health Check",
            "method": "GET",
            "endpoint": "/health",
            "data": None,
            "concurrent": 50,
            "total": 200
        },
        {
            "name": "NCLEX Generation",
            "method": "POST",
            "endpoint": "/api/v1/nclex/generate",
            "data": {
                "topic": "Cardiovascular Nursing",
                "question_count": 5,
                "difficulty": "intermediate"
            },
            "concurrent": 10,
            "total": 50
        },
        {
            "name": "Student Analytics",
            "method": "GET",
            "endpoint": "/api/v1/analytics/student/test_student_123/progress",
            "data": None,
            "concurrent": 20,
            "total": 100
        },
        {
            "name": "Competency Assessment",
            "method": "POST",
            "endpoint": "/api/v1/assessment/competency",
            "data": {
                "student_id": "test_student_123",
                "competency_id": "AACN_KNOWLEDGE_1",
                "performance_data": {
                    "quiz_scores": [85, 90, 88],
                    "clinical_evaluation": {"patient_care": 4.2}
                }
            },
            "concurrent": 15,
            "total": 75
        }
    ]

    print("Starting load test...")
    start_time = time.time()

    for scenario in test_scenarios:
        print(f"\nTesting: {scenario['name']}")
        await tester.test_endpoint(
            method=scenario["method"],
            endpoint=scenario["endpoint"],
            data=scenario["data"],
            concurrent_requests=scenario["concurrent"],
            total_requests=scenario["total"]
        )

    total_time = time.time() - start_time
    tester.print_results()

    print(f"\nTotal test duration: {total_time:.2f} seconds")
    print(f"Total requests: {len(tester.results)}")
    print(f"Average throughput: {len(tester.results)/total_time:.2f} requests/second")

if __name__ == "__main__":
    asyncio.run(run_load_test())
```

## Maintenance and Updates

### Update Procedures

#### Rolling Update Script

```bash
#!/bin/bash
# scripts/rolling-update.sh

set -e

DEPLOYMENT_NAME="bsn-knowledge-app"
NAMESPACE="bsn-knowledge"
NEW_IMAGE_TAG=$1

if [ -z "$NEW_IMAGE_TAG" ]; then
    echo "Usage: $0 <new_image_tag>"
    exit 1
fi

echo "Starting rolling update to version: $NEW_IMAGE_TAG"

# Pre-update health check
echo "Checking system health before update..."
kubectl get pods -n $NAMESPACE
kubectl get svc -n $NAMESPACE

# Update deployment image
echo "Updating deployment image..."
kubectl set image deployment/$DEPLOYMENT_NAME \
    bsn-knowledge=bsn-knowledge:$NEW_IMAGE_TAG \
    -n $NAMESPACE

# Wait for rollout to complete
echo "Waiting for rollout to complete..."
kubectl rollout status deployment/$DEPLOYMENT_NAME -n $NAMESPACE --timeout=600s

# Verify new pods are running
echo "Verifying new pods..."
kubectl get pods -n $NAMESPACE -l app=bsn-knowledge-app

# Health check on updated service
echo "Performing post-update health check..."
sleep 30
kubectl exec -n $NAMESPACE deployment/$DEPLOYMENT_NAME -- curl -f http://localhost:8000/health

echo "Rolling update completed successfully!"

# Optional: Clean up old replica sets
kubectl get rs -n $NAMESPACE | grep bsn-knowledge-app | grep "0         0         0" | awk '{print $1}' | xargs -r kubectl delete rs -n $NAMESPACE
```

#### Backup Before Update

```bash
#!/bin/bash
# scripts/pre-update-backup.sh

set -e

echo "Creating pre-update backup..."

# Database backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/opt/bsn-knowledge/backups/pre_update_$TIMESTAMP.sql"

pg_dump -h localhost -U bsn_user -d bsn_knowledge -f $BACKUP_FILE
gzip $BACKUP_FILE

# Configuration backup
tar -czf "/opt/bsn-knowledge/backups/config_backup_$TIMESTAMP.tar.gz" \
    /opt/bsn-knowledge/config/ \
    /etc/nginx/sites-available/bsn-knowledge \
    /etc/systemd/system/bsn-knowledge.service

# Upload backups to S3 (if configured)
if [ ! -z "$S3_BACKUP_BUCKET" ]; then
    aws s3 cp "$BACKUP_FILE.gz" "s3://$S3_BACKUP_BUCKET/pre-update/"
    aws s3 cp "/opt/bsn-knowledge/backups/config_backup_$TIMESTAMP.tar.gz" "s3://$S3_BACKUP_BUCKET/pre-update/"
fi

echo "Pre-update backup completed successfully!"
echo "Database backup: $BACKUP_FILE.gz"
echo "Config backup: /opt/bsn-knowledge/backups/config_backup_$TIMESTAMP.tar.gz"
```

### Health Checks and Monitoring

#### Comprehensive Health Check

```python
# scripts/health_check.py
import asyncio
import aiohttp
import asyncpg
import redis
import json
import time
from dataclasses import dataclass, asdict
from typing import List, Optional

@dataclass
class ServiceStatus:
    name: str
    status: str  # 'healthy', 'degraded', 'unhealthy'
    response_time: float
    details: dict
    error: Optional[str] = None

class HealthChecker:
    def __init__(self, config: dict):
        self.config = config
        self.results: List[ServiceStatus] = []

    async def check_api_health(self) -> ServiceStatus:
        """Check main API health."""
        start_time = time.time()

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"{self.config['api_url']}/health") as response:
                    response_time = time.time() - start_time

                    if response.status == 200:
                        data = await response.json()
                        return ServiceStatus(
                            name="API",
                            status="healthy",
                            response_time=response_time,
                            details=data
                        )
                    else:
                        return ServiceStatus(
                            name="API",
                            status="unhealthy",
                            response_time=response_time,
                            details={},
                            error=f"HTTP {response.status}"
                        )

        except Exception as e:
            response_time = time.time() - start_time
            return ServiceStatus(
                name="API",
                status="unhealthy",
                response_time=response_time,
                details={},
                error=str(e)
            )

    async def check_database_health(self) -> ServiceStatus:
        """Check PostgreSQL database health."""
        start_time = time.time()

        try:
            conn = await asyncpg.connect(self.config['database_url'])

            # Test basic connectivity
            result = await conn.fetchval("SELECT 1")

            # Check database stats
            stats = await conn.fetchrow("""
                SELECT
                    datname,
                    numbackends,
                    xact_commit,
                    xact_rollback
                FROM pg_stat_database
                WHERE datname = current_database()
            """)

            await conn.close()
            response_time = time.time() - start_time

            return ServiceStatus(
                name="Database",
                status="healthy",
                response_time=response_time,
                details={
                    "connected": True,
                    "active_connections": stats['numbackends'],
                    "committed_transactions": stats['xact_commit'],
                    "rolled_back_transactions": stats['xact_rollback']
                }
            )

        except Exception as e:
            response_time = time.time() - start_time
            return ServiceStatus(
                name="Database",
                status="unhealthy",
                response_time=response_time,
                details={},
                error=str(e)
            )

    async def check_redis_health(self) -> ServiceStatus:
        """Check Redis health."""
        start_time = time.time()

        try:
            redis_client = redis.from_url(self.config['redis_url'])

            # Test basic connectivity
            pong = redis_client.ping()

            # Get Redis info
            info = redis_client.info()

            redis_client.close()
            response_time = time.time() - start_time

            return ServiceStatus(
                name="Redis",
                status="healthy" if pong else "unhealthy",
                response_time=response_time,
                details={
                    "connected": pong,
                    "used_memory": info.get('used_memory_human'),
                    "connected_clients": info.get('connected_clients'),
                    "uptime": info.get('uptime_in_seconds')
                }
            )

        except Exception as e:
            response_time = time.time() - start_time
            return ServiceStatus(
                name="Redis",
                status="unhealthy",
                response_time=response_time,
                details={},
                error=str(e)
            )

    async def check_external_services(self) -> List[ServiceStatus]:
        """Check external service dependencies."""
        services = []

        # Check RAGnostic AI service
        start_time = time.time()
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"{self.config['ragnostic_url']}/health") as response:
                    response_time = time.time() - start_time

                    services.append(ServiceStatus(
                        name="RAGnostic AI",
                        status="healthy" if response.status == 200 else "degraded",
                        response_time=response_time,
                        details={"status_code": response.status}
                    ))

        except Exception as e:
            response_time = time.time() - start_time
            services.append(ServiceStatus(
                name="RAGnostic AI",
                status="degraded",  # Non-critical service
                response_time=response_time,
                details={},
                error=str(e)
            ))

        # Check OpenAI API (if configured)
        if self.config.get('openai_api_key'):
            start_time = time.time()
            try:
                headers = {"Authorization": f"Bearer {self.config['openai_api_key']}"}
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get("https://api.openai.com/v1/models", headers=headers) as response:
                        response_time = time.time() - start_time

                        services.append(ServiceStatus(
                            name="OpenAI API",
                            status="healthy" if response.status == 200 else "degraded",
                            response_time=response_time,
                            details={"status_code": response.status}
                        ))

            except Exception as e:
                response_time = time.time() - start_time
                services.append(ServiceStatus(
                    name="OpenAI API",
                    status="degraded",
                    response_time=response_time,
                    details={},
                    error=str(e)
                ))

        return services

    async def run_all_checks(self) -> dict:
        """Run all health checks and return summary."""

        # Run all checks concurrently
        api_check = asyncio.create_task(self.check_api_health())
        db_check = asyncio.create_task(self.check_database_health())
        redis_check = asyncio.create_task(self.check_redis_health())
        external_checks = asyncio.create_task(self.check_external_services())

        # Wait for all checks to complete
        results = await asyncio.gather(
            api_check, db_check, redis_check, external_checks,
            return_exceptions=True
        )

        self.results = []
        self.results.append(results[0])  # API
        self.results.append(results[1])  # Database
        self.results.append(results[2])  # Redis
        self.results.extend(results[3])  # External services

        # Determine overall health
        critical_services = ["API", "Database", "Redis"]
        critical_unhealthy = any(
            r.status == "unhealthy" and r.name in critical_services
            for r in self.results
        )

        has_degraded = any(r.status == "degraded" for r in self.results)

        if critical_unhealthy:
            overall_status = "unhealthy"
        elif has_degraded:
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        return {
            "overall_status": overall_status,
            "timestamp": time.time(),
            "services": [asdict(r) for r in self.results]
        }

async def main():
    """Run health check and output results."""

    config = {
        "api_url": "http://localhost:8000",
        "database_url": "postgresql://bsn_user:password@localhost:5432/bsn_knowledge",
        "redis_url": "redis://localhost:6379/0",
        "ragnostic_url": "https://ragnostic.internal.edu/api/v1",
        "openai_api_key": None  # Set if you want to check OpenAI API
    }

    checker = HealthChecker(config)
    results = await checker.run_all_checks()

    print(json.dumps(results, indent=2))

    # Exit with appropriate code
    if results["overall_status"] == "unhealthy":
        exit(2)
    elif results["overall_status"] == "degraded":
        exit(1)
    else:
        exit(0)

if __name__ == "__main__":
    asyncio.run(main())
```

This deployment guide provides comprehensive coverage of production deployment scenarios for BSN Knowledge. The configurations and scripts can be adapted based on your specific infrastructure requirements and institutional policies.

For additional deployment support or custom configuration assistance, contact our deployment team at deployment-support@bsn-knowledge.edu.
