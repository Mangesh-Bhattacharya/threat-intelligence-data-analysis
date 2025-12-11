# 🚀 Quick Start Guide

Get the Threat Intelligence Platform running in under 5 minutes!

## Option 1: Docker (Recommended)

**Prerequisites**: Docker and Docker Compose installed

```bash
# Clone repository
git clone https://github.com/Mangesh-Bhattacharya/threat-intelligence-data-analysis.git
cd threat-intelligence-data-analysis

# Start all services
docker-compose up -d

# Access dashboard
open http://localhost:8501
```

**That's it!** The platform is now running with:
- Streamlit Dashboard on port 8501
- PostgreSQL on port 5432
- Redis on port 6379
- Elasticsearch on port 9200
- Prometheus on port 9090
- Grafana on port 3000

## Option 2: Local Python

**Prerequisites**: Python 3.9+

```bash
# Clone repository
git clone https://github.com/Mangesh-Bhattacharya/threat-intelligence-data-analysis.git
cd threat-intelligence-data-analysis

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run dashboard
streamlit run app/dashboard.py
```

Access at: http://localhost:8501

## Option 3: One-Line Deploy

```bash
curl -sSL https://raw.githubusercontent.com/Mangesh-Bhattacharya/threat-intelligence-data-analysis/main/scripts/quick-deploy.sh | bash
```

## First Steps

1. **Explore the Dashboard**
   - Navigate through the 5 tabs
   - View real-time threat data
   - Check AI detection models

2. **Configure Settings**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run Tests**
   ```bash
   pytest tests/ -v
   ```

4. **View Documentation**
   - [Installation Guide](docs/installation.md)
   - [Project Summary](PROJECT_SUMMARY.md)
   - [Security Policy](SECURITY.md)

## Common Commands

```bash
# Stop services
docker-compose down

# View logs
docker-compose logs -f

# Restart services
docker-compose restart

# Update dependencies
pip install -r requirements.txt --upgrade

# Run security scan
bandit -r app/ utils/
```

## Troubleshooting

**Port already in use?**
```bash
# Change port in docker-compose.yml or:
streamlit run app/dashboard.py --server.port=8502
```

**Permission denied?**
```bash
chmod +x scripts/*.sh
```

**Module not found?**
```bash
pip install -r requirements.txt --force-reinstall
```

## Next Steps

- ⭐ Star the repository
- 📖 Read the [full documentation](docs/installation.md)
- 🔐 Review [security best practices](SECURITY.md)
- 🤝 Check [contributing guidelines](CONTRIBUTING.md)

## Support

- 📧 Email: mangesh.bhattacharya@ontariotechu.net
- 🐛 Issues: [GitHub Issues](https://github.com/Mangesh-Bhattacharya/threat-intelligence-data-analysis/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/Mangesh-Bhattacharya/threat-intelligence-data-analysis/discussions)

---

**Happy Threat Hunting! 🛡️**
