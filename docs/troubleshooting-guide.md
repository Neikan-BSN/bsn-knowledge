# BSN Knowledge Troubleshooting Guide

Comprehensive troubleshooting guide for resolving common issues with the BSN Knowledge platform, including diagnostic procedures, error resolution, and escalation protocols.

## Quick Diagnostic Checklist

Before diving into specific issues, run through this quick diagnostic checklist:

### System Status Check
```bash
# Check all services are running
sudo systemctl status bsn-knowledge
sudo systemctl status postgresql
sudo systemctl status redis
sudo systemctl status nginx

# Check network connectivity
curl -f http://localhost:8000/health
ping api.bsn-knowledge.edu

# Check disk space
df -h

# Check memory usage
free -h

# Check recent logs
journalctl -u bsn-knowledge --since "10 minutes ago"
```

### Service Health Verification
```bash
# API Health Check
curl -s http://localhost:8000/health | jq

# Database Connection Test
psql -h localhost -U bsn_user -d bsn_knowledge -c "SELECT 1;"

# Redis Connection Test
redis-cli ping

# Check external dependencies
curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY" | jq '.data | length'
```

## Common Issues and Solutions

### Authentication and Access Issues

#### Issue: "Authentication failed" errors
**Symptoms**: Users unable to log in, 401 errors in API responses
**Common Causes**: Expired tokens, incorrect credentials, configuration issues

**Diagnostic Steps**:
```bash
# Check JWT configuration
grep -i jwt /opt/bsn-knowledge/.env

# Verify user exists in database
psql -h localhost -U bsn_user -d bsn_knowledge -c "SELECT username, is_active FROM users WHERE username='problematic_user';"

# Check authentication logs
grep "Authentication" /opt/bsn-knowledge/logs/api.log | tail -20
```

**Solutions**:

1. **Token Expiration**:
```python
# Check token expiration in application
import jwt
import datetime

def check_token_expiration(token):
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp_timestamp = payload.get('exp')
        if exp_timestamp:
            exp_time = datetime.datetime.fromtimestamp(exp_timestamp)
            print(f"Token expires at: {exp_time}")
            print(f"Current time: {datetime.datetime.now()}")
            print(f"Token valid: {exp_time > datetime.datetime.now()}")
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
```

2. **User Account Issues**:
```sql
-- Reactivate disabled user account
UPDATE users SET is_active = true WHERE username = 'problematic_user';

-- Reset user password
UPDATE users SET hashed_password = '$2b$12$...' WHERE username = 'problematic_user';
```

3. **Configuration Fix**:
```bash
# Update JWT secret in environment file
echo "JWT_SECRET_KEY=your_new_secret_key_here" >> /opt/bsn-knowledge/.env

# Restart service
sudo systemctl restart bsn-knowledge
```

#### Issue: "Access denied" or permission errors
**Symptoms**: 403 errors, users can't access certain features
**Common Causes**: Incorrect role assignments, missing permissions

**Diagnostic Steps**:
```sql
-- Check user roles and permissions
SELECT u.username, u.role, u.is_active
FROM users u
WHERE username = 'problematic_user';

-- Check role-based permissions
SELECT * FROM user_permissions WHERE user_id = (
    SELECT id FROM users WHERE username = 'problematic_user'
);
```

**Solutions**:
```sql
-- Update user role
UPDATE users SET role = 'instructor' WHERE username = 'problematic_user';

-- Grant specific permissions
INSERT INTO user_permissions (user_id, permission)
VALUES ((SELECT id FROM users WHERE username = 'problematic_user'), 'create_content');
```

### Performance Issues

#### Issue: Slow API response times
**Symptoms**: Requests taking >5 seconds, timeouts, poor user experience
**Common Causes**: Database performance, memory issues, external service delays

**Diagnostic Steps**:
```bash
# Check current response times
curl -w "@curl-format.txt" -s -o /dev/null http://localhost:8000/api/v1/nclex/generate

# Monitor system resources
top -p $(pgrep -f "bsn-knowledge")
iostat -x 1 5

# Check database performance
psql -h localhost -U bsn_user -d bsn_knowledge -c "
SELECT query, mean_time, calls
FROM pg_stat_statements
WHERE mean_time > 1000
ORDER BY mean_time DESC
LIMIT 10;
"
```

Create `curl-format.txt`:
```
time_namelookup:  %{time_namelookup}\n
time_connect:     %{time_connect}\n
time_appconnect:  %{time_appconnect}\n
time_pretransfer: %{time_pretransfer}\n
time_redirect:    %{time_redirect}\n
time_starttransfer: %{time_starttransfer}\n
time_total:       %{time_total}\n
```

**Solutions**:

1. **Database Optimization**:
```sql
-- Analyze slow queries
EXPLAIN ANALYZE SELECT * FROM student_profiles WHERE student_id = 'student123';

-- Update table statistics
ANALYZE;

-- Rebuild indexes if needed
REINDEX INDEX idx_student_profiles_student_id;
```

2. **Memory Optimization**:
```bash
# Increase application memory limit
echo "MemoryMax=8G" >> /etc/systemd/system/bsn-knowledge.service
sudo systemctl daemon-reload
sudo systemctl restart bsn-knowledge

# Configure PostgreSQL shared buffers
echo "shared_buffers = 512MB" >> /etc/postgresql/15/main/postgresql.conf
sudo systemctl restart postgresql
```

3. **Caching Configuration**:
```python
# Enable Redis caching for expensive operations
import redis

redis_client = redis.from_url("redis://localhost:6379/0")

# Cache NCLEX questions
def cache_nclex_questions(topic, difficulty, questions):
    cache_key = f"nclex:{topic}:{difficulty}"
    redis_client.setex(cache_key, 3600, json.dumps(questions))  # 1 hour cache
```

#### Issue: High memory usage
**Symptoms**: Out of memory errors, system slowdown, application crashes
**Common Causes**: Memory leaks, large dataset processing, insufficient resources

**Diagnostic Steps**:
```bash
# Monitor memory usage
ps aux --sort=-%mem | head -10

# Check application memory specifically
ps -p $(pgrep -f "bsn-knowledge") -o pid,ppid,%mem,rss,cmd

# Monitor memory over time
watch -n 5 'free -m'
```

**Solutions**:
```bash
# Increase system memory limits
echo "vm.overcommit_memory = 2" >> /etc/sysctl.conf
echo "vm.overcommit_ratio = 80" >> /etc/sysctl.conf
sysctl -p

# Configure application memory limits
export PYTHONMALLOC=malloc
export MALLOC_TRIM_THRESHOLD_=100000

# Restart with memory optimization
sudo systemctl restart bsn-knowledge
```

### Database Issues

#### Issue: Database connection failures
**Symptoms**: "Connection refused", "database unavailable" errors
**Common Causes**: PostgreSQL not running, connection limits exceeded, network issues

**Diagnostic Steps**:
```bash
# Check PostgreSQL service
sudo systemctl status postgresql

# Check connection limits
psql -h localhost -U postgres -c "
SELECT setting FROM pg_settings WHERE name = 'max_connections';
SELECT count(*) as current_connections FROM pg_stat_activity;
"

# Test direct connection
psql -h localhost -U bsn_user -d bsn_knowledge -c "SELECT version();"
```

**Solutions**:
```bash
# Start PostgreSQL if stopped
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Increase connection limits
echo "max_connections = 200" >> /etc/postgresql/15/main/postgresql.conf
sudo systemctl restart postgresql

# Kill hanging connections
psql -h localhost -U postgres -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = 'bsn_knowledge'
AND state = 'idle'
AND state_change < now() - interval '1 hour';
"
```

#### Issue: Database corruption or data inconsistency
**Symptoms**: Data retrieval errors, inconsistent results, referential integrity violations
**Common Causes**: Improper shutdowns, disk issues, concurrent access problems

**Diagnostic Steps**:
```sql
-- Check for corrupted indexes
SELECT schemaname, tablename, indexname
FROM pg_indexes
WHERE schemaname = 'public';

-- Verify referential integrity
SELECT conname, conrelid::regclass, confrelid::regclass
FROM pg_constraint
WHERE contype = 'f'
AND NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgconstraint = pg_constraint.oid
);

-- Check for duplicate keys
SELECT student_id, count(*)
FROM student_profiles
GROUP BY student_id
HAVING count(*) > 1;
```

**Solutions**:
```bash
# Create backup before repair
pg_dump -h localhost -U bsn_user bsn_knowledge > backup_before_repair.sql

# Run database integrity checks
psql -h localhost -U bsn_user -d bsn_knowledge -c "
SET client_min_messages TO WARNING;
\echo 'Checking table integrity...'
SELECT schemaname, tablename
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;
"

# Reindex all tables
psql -h localhost -U bsn_user -d bsn_knowledge -c "REINDEX DATABASE bsn_knowledge;"
```

### Content Generation Issues

#### Issue: NCLEX question generation failures
**Symptoms**: Empty responses, error messages, timeouts during question creation
**Common Causes**: OpenAI API issues, prompt problems, rate limiting

**Diagnostic Steps**:
```bash
# Check OpenAI API connectivity
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     -H "Content-Type: application/json" \
     "https://api.openai.com/v1/models"

# Check generation logs
grep -i "nclex.*generation" /opt/bsn-knowledge/logs/api.log | tail -20

# Test generation endpoint directly
curl -X POST http://localhost:8000/api/v1/nclex/generate \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"topic": "test", "question_count": 1}'
```

**Solutions**:

1. **OpenAI API Issues**:
```python
# Check API key validity
import openai

try:
    openai.api_key = "your_api_key"
    models = openai.Model.list()
    print("API key is valid")
except Exception as e:
    print(f"API key issue: {e}")
```

2. **Rate Limiting**:
```python
# Implement exponential backoff
import time
import random

def retry_with_backoff(func, max_retries=3):
    for attempt in range(max_retries):
        try:
            return func()
        except openai.error.RateLimitError:
            if attempt == max_retries - 1:
                raise
            wait_time = (2 ** attempt) + random.uniform(0, 1)
            print(f"Rate limited, waiting {wait_time:.2f} seconds")
            time.sleep(wait_time)
```

3. **Content Quality Issues**:
```python
# Improve prompt engineering
def create_better_nclex_prompt(topic, difficulty):
    prompt = f"""
    Create a high-quality NCLEX-RN style question about {topic}
    at {difficulty} difficulty level.

    Requirements:
    - Must test critical thinking, not just memorization
    - Include realistic clinical scenario
    - Provide evidence-based rationale
    - Follow NCLEX question format exactly
    - Ensure medical accuracy

    Topic: {topic}
    Difficulty: {difficulty}
    """
    return prompt
```

#### Issue: Study guide generation problems
**Symptoms**: Incomplete guides, formatting issues, irrelevant content
**Common Causes**: Template problems, data retrieval issues, AI model limitations

**Solutions**:
```python
# Enhanced study guide generation
def generate_study_guide_with_validation(topic, level):
    try:
        # Generate content with multiple attempts
        for attempt in range(3):
            guide = generate_study_guide_content(topic, level)

            # Validate content quality
            if validate_study_guide_quality(guide):
                return guide
            else:
                print(f"Attempt {attempt + 1} failed validation, retrying...")

        raise Exception("Failed to generate quality study guide after 3 attempts")

    except Exception as e:
        # Fallback to template-based generation
        return generate_fallback_study_guide(topic, level)

def validate_study_guide_quality(guide):
    """Validate study guide meets quality standards."""
    checks = [
        len(guide.get('content', '')) > 100,  # Minimum content length
        'learning_objectives' in guide,        # Has learning objectives
        len(guide.get('sections', [])) >= 3,   # Minimum sections
        guide.get('topic') is not None         # Has topic
    ]
    return all(checks)
```

### External Service Integration Issues

#### Issue: RAGnostic service connectivity problems
**Symptoms**: Content enrichment failures, empty medical terminology data
**Common Causes**: Network issues, service downtime, authentication problems

**Diagnostic Steps**:
```bash
# Test RAGnostic connectivity
curl -f https://ragnostic.internal.edu/api/v1/health

# Check authentication
curl -H "Authorization: Bearer $RAGNOSTIC_API_KEY" \
     https://ragnostic.internal.edu/api/v1/content/search

# Monitor network latency
ping ragnostic.internal.edu
traceroute ragnostic.internal.edu
```

**Solutions**:
```python
# Implement circuit breaker pattern
class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN

    def call(self, func, *args, **kwargs):
        if self.state == 'OPEN':
            if time.time() - self.last_failure_time > self.timeout:
                self.state = 'HALF_OPEN'
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)
            if self.state == 'HALF_OPEN':
                self.state = 'CLOSED'
                self.failure_count = 0
            return result

        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.failure_threshold:
                self.state = 'OPEN'

            raise e

# Usage
ragnostic_breaker = CircuitBreaker()

def get_ragnostic_content(query):
    return ragnostic_breaker.call(ragnostic_api_call, query)
```

### User Interface and Experience Issues

#### Issue: Users unable to access certain features
**Symptoms**: Missing menu items, disabled buttons, blank pages
**Common Causes**: Role permissions, JavaScript errors, browser compatibility

**Diagnostic Steps**:
```bash
# Check user permissions in database
psql -h localhost -U bsn_user -d bsn_knowledge -c "
SELECT u.username, u.role, up.permission
FROM users u
LEFT JOIN user_permissions up ON u.id = up.user_id
WHERE u.username = 'problematic_user';
"

# Check browser console logs (advise user)
echo "Ask user to check browser console for JavaScript errors"

# Verify API endpoints are accessible
curl -H "Authorization: Bearer $USER_TOKEN" \
     http://localhost:8000/api/v1/auth/me
```

**Solutions**:
```sql
-- Grant missing permissions
INSERT INTO user_permissions (user_id, permission)
SELECT u.id, 'create_content'
FROM users u
WHERE u.username = 'username'
AND NOT EXISTS (
    SELECT 1 FROM user_permissions up
    WHERE up.user_id = u.id
    AND up.permission = 'create_content'
);

-- Update user role
UPDATE users
SET role = 'instructor'
WHERE username = 'username'
AND role = 'student';
```

#### Issue: Data not loading or displaying incorrectly
**Symptoms**: Spinner keeps loading, incorrect data shown, stale information
**Common Causes**: Caching issues, API errors, browser cache

**Solutions**:
```bash
# Clear Redis cache
redis-cli FLUSHDB

# Restart application to clear memory cache
sudo systemctl restart bsn-knowledge

# Clear browser cache (instruct user)
echo "Ask user to clear browser cache and cookies for the site"
```

## Advanced Troubleshooting

### Log Analysis

#### Structured Log Analysis
```bash
# Parse application logs for errors
grep -E "(ERROR|CRITICAL)" /opt/bsn-knowledge/logs/api.log | \
  tail -50 | \
  awk '{print $1, $2, $5}' | \
  sort | uniq -c | sort -nr

# Find most common error patterns
grep "ERROR" /opt/bsn-knowledge/logs/api.log | \
  sed 's/.*ERROR.*: //' | \
  sort | uniq -c | sort -nr | head -10

# Analyze request patterns
grep "API Request" /opt/bsn-knowledge/logs/api.log | \
  awk '{print $8}' | \
  sort | uniq -c | sort -nr | head -20
```

#### Performance Log Analysis
```bash
# Find slow requests
grep "Duration:" /opt/bsn-knowledge/logs/api.log | \
  awk '$NF > 5000 {print}' | \
  tail -20

# Analyze response time trends
grep "Duration:" /opt/bsn-knowledge/logs/api.log | \
  awk '{print $(NF-1), $NF}' | \
  sort -k2 -nr | \
  head -20
```

### Database Deep Dive

#### Advanced Database Diagnostics
```sql
-- Find long-running queries
SELECT
    pid,
    now() - pg_stat_activity.query_start AS duration,
    query
FROM pg_stat_activity
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes'
ORDER BY duration DESC;

-- Check for lock contention
SELECT
    blocked_locks.pid AS blocked_pid,
    blocked_activity.usename AS blocked_user,
    blocking_locks.pid AS blocking_pid,
    blocking_activity.usename AS blocking_user,
    blocked_activity.query AS blocked_statement,
    blocking_activity.query AS blocking_statement
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks
    ON blocking_locks.locktype = blocked_locks.locktype
    AND blocking_locks.database IS NOT DISTINCT FROM blocked_locks.database
    AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
    AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
    AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
    AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid
    AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid
    AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid
    AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid
    AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid
    AND blocking_locks.pid != blocked_locks.pid
JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.granted;

-- Analyze table sizes and growth
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) as index_size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

### Security Issue Investigation

#### Security Incident Response
```bash
# Check for suspicious login attempts
grep -i "authentication.*failed" /opt/bsn-knowledge/logs/api.log | \
  grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | \
  sort | uniq -c | sort -nr

# Monitor for brute force attacks
grep "401.*Unauthorized" /var/log/nginx/access.log | \
  awk '{print $1}' | \
  sort | uniq -c | \
  awk '$1 > 10 {print}' | \
  sort -nr

# Check for SQL injection attempts
grep -i "select\|union\|drop\|delete" /opt/bsn-knowledge/logs/api.log | \
  grep -v "normal_operation"

# Verify file integrity
find /opt/bsn-knowledge -name "*.py" -exec sha256sum {} \; > current_checksums.txt
diff original_checksums.txt current_checksums.txt
```

## Escalation Procedures

### When to Escalate

**Immediate Escalation (Call Emergency Support)**:
- Complete system outage affecting all users
- Data corruption or loss
- Security breach or compromise
- Patient safety-related issues

**Priority Escalation (Contact Support Within 2 Hours)**:
- Service degradation affecting >25% of users
- Authentication system failures
- Database connectivity issues
- External service integration failures

**Standard Escalation (Submit Support Ticket)**:
- Individual user issues
- Feature requests
- Performance optimization
- Documentation updates

### Escalation Contacts

```bash
# Emergency Contacts (24/7)
EMERGENCY_PHONE="+1-800-BSN-CRIT"
EMERGENCY_EMAIL="emergency@bsn-knowledge.edu"

# Technical Support
TECH_SUPPORT_EMAIL="tech-support@bsn-knowledge.edu"
TECH_SUPPORT_PHONE="+1-800-BSN-TECH"

# Security Team
SECURITY_EMAIL="security@bsn-knowledge.edu"
SECURITY_PHONE="+1-800-BSN-SEC"
```

### Information to Include in Escalation

#### System Information
```bash
# Gather system information for escalation
cat > escalation-info.txt << EOF
BSN Knowledge System Information
================================
Date: $(date)
Hostname: $(hostname)
OS Version: $(cat /etc/os-release | grep PRETTY_NAME)
Kernel: $(uname -r)
Uptime: $(uptime)

Service Status:
$(systemctl is-active bsn-knowledge postgresql redis nginx)

Resource Usage:
$(free -h)
$(df -h)

Recent Errors:
$(journalctl -u bsn-knowledge --since "1 hour ago" | grep ERROR | tail -10)

Database Status:
$(psql -h localhost -U bsn_user -d bsn_knowledge -c "SELECT version();" 2>&1)

Network Connectivity:
$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health)
EOF

echo "System information gathered in escalation-info.txt"
```

#### Error Documentation Template
```markdown
## Issue Summary
Brief description of the problem

## Impact Assessment
- Affected users: [number/percentage]
- Services impacted: [list services]
- Business impact: [critical/high/medium/low]

## Timeline
- Issue first detected: [timestamp]
- Users first reported: [timestamp]
- Investigation started: [timestamp]

## Symptoms Observed
- [List specific symptoms]
- [Include error messages]
- [Attach screenshots if relevant]

## Diagnostic Steps Taken
1. [Step 1 and result]
2. [Step 2 and result]
3. [Step 3 and result]

## Temporary Workarounds
- [Any workarounds implemented]
- [User communication sent]

## Additional Information
- Log files: [attach relevant logs]
- System information: [attach system info]
- Recent changes: [any recent deployments or changes]
```

## Prevention and Best Practices

### Monitoring Setup

#### Automated Health Monitoring
```bash
#!/bin/bash
# /opt/bsn-knowledge/scripts/health-monitor.sh

LOG_FILE="/opt/bsn-knowledge/logs/health-monitor.log"
ALERT_EMAIL="admin@university.edu"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOG_FILE
}

check_service() {
    local service=$1
    if systemctl is-active --quiet $service; then
        log_message "✓ $service is running"
        return 0
    else
        log_message "✗ $service is not running"
        return 1
    fi
}

check_endpoint() {
    local endpoint=$1
    local expected_status=${2:-200}

    status=$(curl -s -o /dev/null -w "%{http_code}" $endpoint)
    if [ "$status" = "$expected_status" ]; then
        log_message "✓ $endpoint responded with $status"
        return 0
    else
        log_message "✗ $endpoint responded with $status (expected $expected_status)"
        return 1
    fi
}

# Run health checks
failed_checks=0

# Service checks
for service in bsn-knowledge postgresql redis nginx; do
    if ! check_service $service; then
        ((failed_checks++))
    fi
done

# Endpoint checks
endpoints=(
    "http://localhost:8000/health"
    "http://localhost:8000/metrics"
)

for endpoint in "${endpoints[@]}"; do
    if ! check_endpoint $endpoint; then
        ((failed_checks++))
    fi
done

# Database connectivity check
if ! psql -h localhost -U bsn_user -d bsn_knowledge -c "SELECT 1;" >/dev/null 2>&1; then
    log_message "✗ Database connectivity failed"
    ((failed_checks++))
fi

# Redis connectivity check
if ! redis-cli ping >/dev/null 2>&1; then
    log_message "✗ Redis connectivity failed"
    ((failed_checks++))
fi

# Send alert if any checks failed
if [ $failed_checks -gt 0 ]; then
    log_message "ALERT: $failed_checks health checks failed"

    # Send email alert
    mail -s "BSN Knowledge Health Check Alert - $failed_checks failures" $ALERT_EMAIL < $LOG_FILE

    exit 1
else
    log_message "All health checks passed"
    exit 0
fi
```

#### Automated Log Rotation
```bash
# /etc/logrotate.d/bsn-knowledge
/opt/bsn-knowledge/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 bsn-knowledge bsn-knowledge
    postrotate
        systemctl reload bsn-knowledge
    endscript
}

/var/log/nginx/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 www-data www-data
    postrotate
        systemctl reload nginx
    endscript
}
```

### Preventive Maintenance

#### Weekly Maintenance Tasks
```bash
#!/bin/bash
# /opt/bsn-knowledge/scripts/weekly-maintenance.sh

# Update system packages
apt update && apt upgrade -y

# Clean old logs
find /opt/bsn-knowledge/logs -name "*.log.*" -mtime +30 -delete

# Vacuum database
psql -h localhost -U bsn_user -d bsn_knowledge -c "VACUUM ANALYZE;"

# Clean Redis cache of expired keys
redis-cli --scan --pattern "*" | xargs -L 1 redis-cli TTL | grep -c "^-1$"

# Check disk space
df -h | awk '$5 > 80 {print "Warning: " $1 " is " $5 " full"}'

# Generate health report
/opt/bsn-knowledge/scripts/health-monitor.sh

# Restart services to clear memory
systemctl restart bsn-knowledge
```

#### Monthly Maintenance Tasks
```bash
#!/bin/bash
# /opt/bsn-knowledge/scripts/monthly-maintenance.sh

# Full database backup
pg_dump -h localhost -U bsn_user bsn_knowledge | gzip > "/opt/bsn-knowledge/backups/monthly_backup_$(date +%Y%m).sql.gz"

# Update SSL certificates
certbot renew --quiet

# Security updates
apt update && apt upgrade -y
apt autoremove -y
apt autoclean

# Review user accounts
psql -h localhost -U bsn_user -d bsn_knowledge -c "
SELECT username, last_login, is_active
FROM users
WHERE last_login < NOW() - INTERVAL '90 days'
AND is_active = true;
"

# Performance analysis
psql -h localhost -U bsn_user -d bsn_knowledge -c "
SELECT query, calls, mean_time, total_time
FROM pg_stat_statements
ORDER BY total_time DESC
LIMIT 10;
" > /opt/bsn-knowledge/reports/monthly_performance_$(date +%Y%m).txt
```

---

## Emergency Procedures

### Complete System Recovery

#### Disaster Recovery Checklist
```bash
#!/bin/bash
# disaster-recovery.sh

echo "BSN Knowledge Disaster Recovery Procedure"
echo "======================================="

# 1. Assess system state
echo "Step 1: Assessing system state..."
systemctl status bsn-knowledge postgresql redis nginx

# 2. Stop all services
echo "Step 2: Stopping all services..."
systemctl stop bsn-knowledge nginx
systemctl stop postgresql redis

# 3. Restore from backup
echo "Step 3: Restoring from backup..."
echo "Available backups:"
ls -la /opt/bsn-knowledge/backups/

read -p "Enter backup file name to restore: " backup_file

if [ -f "/opt/bsn-knowledge/backups/$backup_file" ]; then
    # Restore database
    dropdb -h localhost -U bsn_user bsn_knowledge
    createdb -h localhost -U bsn_user bsn_knowledge

    if [[ $backup_file == *.gz ]]; then
        gunzip -c "/opt/bsn-knowledge/backups/$backup_file" | psql -h localhost -U bsn_user bsn_knowledge
    else
        psql -h localhost -U bsn_user bsn_knowledge < "/opt/bsn-knowledge/backups/$backup_file"
    fi

    echo "Database restored successfully"
else
    echo "Backup file not found!"
    exit 1
fi

# 4. Start services
echo "Step 4: Starting services..."
systemctl start postgresql redis
systemctl start bsn-knowledge nginx

# 5. Verify recovery
echo "Step 5: Verifying recovery..."
sleep 10

curl -f http://localhost:8000/health && echo "✓ API is responding"
psql -h localhost -U bsn_user -d bsn_knowledge -c "SELECT count(*) FROM users;" && echo "✓ Database is accessible"
redis-cli ping && echo "✓ Redis is responding"

echo "Disaster recovery completed!"
```

This troubleshooting guide provides comprehensive coverage of common issues and their resolutions. Keep this document updated as new issues are discovered and resolved.

**For additional support beyond this guide, contact BSN Knowledge Technical Support:**
- **Email**: support@bsn-knowledge.edu
- **Phone**: 1-800-BSN-HELP
- **Emergency**: 1-800-BSN-CRIT (24/7)
