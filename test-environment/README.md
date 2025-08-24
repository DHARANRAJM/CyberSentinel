# CyberSentinel Test Environment

This directory contains a secure, isolated environment for testing web application security. It includes several intentionally vulnerable applications and security tools.

## Prerequisites

- Docker
- Docker Compose
- At least 4GB of free RAM
- At least 5GB of free disk space

## Available Applications

1. **OWASP Juice Shop** - Modern vulnerable web application
   - URL: http://localhost:3000
   - Default credentials: `admin@juice-sh.op` / `admin123`

2. **DVWA (Damn Vulnerable Web App)**
   - URL: http://localhost:8080
   - Default credentials: `admin` / `password`

3. **WebGoat**
   - URL: http://localhost:8081/WebGoat
   - Create an account on first launch

4. **OWASP ZAP** (Security Scanner)
   - URL: http://localhost:8090
   - No authentication required in this setup

5. **Metasploitable2**
   - Various vulnerable services (FTP, SSH, HTTP, etc.)
   - Default credentials: `msfadmin` / `msfadmin`

## Getting Started

1. Make sure Docker is running on your system
2. Open a terminal in this directory
3. Run: `docker-compose up -d`
4. Access the applications using the URLs above

## Security Notes

- These applications are intentionally vulnerable - do not expose them to the internet
- All containers are isolated from your host system and each other
- Data will persist between container restarts

## Stopping the Environment

To stop all containers:
```bash
docker-compose down
```

## Cleaning Up

To remove all containers and data:
```bash
docker-compose down -v
```
