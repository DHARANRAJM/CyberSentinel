# CyberSentinel Pro - Deployment Guide

## Quick Start

### 1. Environment Setup
```bash
# Copy environment template
cp deploy/.env.example deploy/.env

# Edit the environment file with your settings
# At minimum, set:
# - POSTGRES_PASSWORD
# - JWT_SECRET_KEY
# - API_SECRET_KEY
```

### 2. Deploy with Docker Compose
```bash
# Navigate to deployment directory
cd deploy/

# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### 3. Initialize Database
```bash
# Create database tables (run once)
docker-compose exec api python -c "
from app.database import engine
from app.models import Base
Base.metadata.create_all(bind=engine)
print('Database initialized successfully')
"

# Create admin user (optional)
docker-compose exec api python -c "
from app.database import SessionLocal
from app.models import User
from app.auth import get_password_hash
import uuid

db = SessionLocal()
admin_user = User(
    id=str(uuid.uuid4()),
    email='admin@cybersentinel.local',
    hashed_password=get_password_hash('admin123'),
    role='admin',
    is_active=True
)
db.add(admin_user)
db.commit()
print('Admin user created: admin@cybersentinel.local / admin123')
"
```

### 4. Deploy Agent
```bash
# On target systems, copy agent files
cp -r agent/ /opt/cybersentinel-agent/
cd /opt/cybersentinel-agent/

# Install dependencies
pip install -r requirements.txt

# Configure agent
cp config.yaml.example config.yaml
# Edit config.yaml with your API URL and key

# Run agent
python agent.py
```

## Service URLs

- **Web Dashboard**: http://localhost:3000
- **API Backend**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **MinIO Console**: http://localhost:9001 (admin/password123)

## Production Deployment

### Security Hardening
1. **TLS/SSL**: Configure nginx with SSL certificates
2. **Firewall**: Restrict access to necessary ports only
3. **Secrets**: Use proper secret management (HashiCorp Vault, AWS Secrets Manager)
4. **Database**: Use managed database service with encryption
5. **Monitoring**: Set up log aggregation and monitoring

### Scaling
1. **Load Balancer**: Add nginx/HAProxy for multiple API instances
2. **Database**: Use PostgreSQL cluster or managed service
3. **Redis**: Use Redis Cluster for high availability
4. **Workers**: Scale Celery workers horizontally

### Backup Strategy
1. **Database**: Regular PostgreSQL backups
2. **Configuration**: Version control all config files
3. **Logs**: Centralized logging with retention policies

## Troubleshooting

### Common Issues

**Services won't start:**
```bash
# Check logs
docker-compose logs api
docker-compose logs db
docker-compose logs redis

# Restart services
docker-compose restart
```

**Database connection issues:**
```bash
# Check database is running
docker-compose exec db psql -U cybersentinel -d cybersentinel -c "SELECT version();"

# Reset database
docker-compose down -v
docker-compose up -d
```

**Agent connection issues:**
```bash
# Test API connectivity
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/v1/ingest/heartbeat

# Check agent logs
tail -f agent.log
```

### Performance Tuning

**Database:**
- Increase `shared_buffers` for PostgreSQL
- Enable query logging for slow queries
- Set up proper indexes

**Redis:**
- Configure memory limits
- Enable persistence if needed

**API:**
- Tune worker processes
- Configure connection pooling
- Enable response caching

## Monitoring

### Health Checks
- API: `GET /health`
- Database: Connection test
- Redis: `PING` command
- Agent: Heartbeat frequency

### Metrics to Monitor
- API response times
- Database query performance
- Redis memory usage
- Agent connectivity
- Alert processing latency
- Disk space usage

### Alerting
Set up alerts for:
- Service downtime
- High error rates
- Database connection failures
- Disk space low
- Memory usage high
