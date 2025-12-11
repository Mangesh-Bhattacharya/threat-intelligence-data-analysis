# Installation Guide

## Prerequisites

- Python 3.9 or higher
- Docker (optional, for containerized deployment)
- Git
- 4GB RAM minimum (8GB recommended)
- 10GB free disk space

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/Mangesh-Bhattacharya/threat-intelligence-data-analysis.git
cd threat-intelligence-data-analysis
```

### 2. Virtual Environment Setup

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Environment Configuration

```bash
cp .env.example .env
# Edit .env with your configuration
nano .env  # or use your preferred editor
```

### 5. Run Application

```bash
streamlit run app/dashboard.py
```

Access dashboard at: `http://localhost:8501`

## Docker Installation

### Using Docker Compose (Recommended)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Using Docker Only

```bash
# Build image
docker build -t threat-intel-platform .

# Run container
docker run -p 8501:8501 threat-intel-platform
```

## Cloud Deployment

### AWS

```bash
# Using AWS ECS
aws ecs create-cluster --cluster-name threat-intel-cluster
# Deploy using provided CloudFormation template
```

### Azure

```bash
# Using Azure Container Instances
az container create --resource-group threat-intel-rg \
  --name threat-intel-app \
  --image threat-intel-platform:latest \
  --ports 8501
```

### GCP

```bash
# Using Google Cloud Run
gcloud run deploy threat-intel-platform \
  --image gcr.io/PROJECT_ID/threat-intel-platform \
  --platform managed
```

## Database Setup

### PostgreSQL

```bash
# Create database
createdb threat_intel

# Run migrations
python scripts/migrate.py
```

### Redis

```bash
# Start Redis
redis-server

# Or using Docker
docker run -d -p 6379:6379 redis:7-alpine
```

## Verification

```bash
# Run tests
pytest tests/ -v

# Check installation
python -c "import streamlit; import pandas; import sklearn; print('All dependencies installed!')"
```

## Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Change port in .env or use:
streamlit run app/dashboard.py --server.port=8502
```

**Module not found:**
```bash
pip install -r requirements.txt --force-reinstall
```

**Permission denied:**
```bash
chmod +x scripts/*.sh
```

## Next Steps

- Configure threat intelligence feeds in `.env`
- Set up cloud storage credentials
- Configure SIEM integration
- Review security settings

For detailed configuration, see [Configuration Guide](configuration.md)
