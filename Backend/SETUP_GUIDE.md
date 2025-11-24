# Vaptiq.ai Backend Configuration Guide

## 🔧 Environment Variables

Create a `.env` file in the `Backend` directory with the following variables:

### Core Configuration
```bash
# CORS Origins (comma-separated)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001

# Redis Connection (for Celery task queue)
REDIS_URL=redis://localhost:6379/0
```

### Database Configuration (Prisma + PostgreSQL)
```bash
# PostgreSQL Database URL
# Format: postgresql://USER:PASSWORD@HOST:PORT/DATABASE
# Example from Supabase:
DATABASE_URL="postgresql://postgres:your_password@db.xxx.supabase.co:5432/postgres"
```

**Setup Steps:**
1. Sign up at [Supabase](https://supabase.com) (free tier available)
2. Create a new project
3. Copy the "Connection String" from Settings → Database
4. Run Prisma migrations:
   ```bash
   cd Backend
   prisma generate
   prisma db push
   ```

### E2B Secure Sandbox
```bash
# E2B API Key for secure code execution
# Get your free key at https://e2b.dev
E2B_API_KEY=e2b_...
```

**Setup Steps:**
1. Sign up at [E2B](https://e2b.dev)
2. Create an API key from the dashboard
3. Add to `.env` file

> **Note:** Without E2B_API_KEY, the verifier will fallback to mock mode (safe for testing)

### LLM Provider Configuration
```bash
# --- Option 1: OpenRouter (Multi-model support) ---
LLM_PROVIDER=OPENROUTER
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_MODEL=moonshotai/kimi-k2-thinking

# --- Option 2: Direct Gemini (Privacy Mode) ---
LLM_PROVIDER=GEMINI
GEMINI_API_KEY=...
PRIVACY_MODE=HIGH  # Forces direct APIs, bypasses third-party aggregators

# --- Option 3: Kimi Direct ---
LLM_PROVIDER=KIMI
MOONSHOT_API_KEY=...
```

### Deprecated (Do NOT use in production)
```bash
# DANGER: Only for testing. Use E2B instead!
# ENABLE_CODE_EXECUTION=false  # Keep disabled
```

---

## 🚀 Deployment Checklist

### 1. Install Dependencies
```bash
cd Backend
pip install -r requirements.txt
```

### 2. Install Nmap (Required for scanning)
**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**MacOS:**
```bash
brew install nmap
```

**Windows:**
Download from [nmap.org](https://nmap.org/download.html)

### 3. Setup Database
```bash
# Navigate to Backend directory
cd Backend

# Generate Prisma client
prisma generate

# Push schema to database
prisma db push
```

### 4. Start Redis (required for Celery)
**Using Docker:**
```bash
docker run -d -p 6379:6379 redis:alpine
```

**Or install locally:**
```bash
# Linux
sudo apt-get install redis-server
sudo systemctl start redis

# MacOS
brew install redis
brew services start redis
```

### 5. Start Celery Worker
```bash
cd Backend
celery -A tasks worker --loglevel=info --pool=solo
```

### 6. Start FastAPI Server
```bash
cd Backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## 🏗️ Docker Deployment (Recommended)

Add `nmap` to your Dockerfile:

```dockerfile
FROM python:3.11-slim

# Install system dependencies including Nmap
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# ... rest of your Dockerfile
```

---

## 🔐 Security Notes

1. **E2B Sandbox**: Always use E2B for production. Never set `ENABLE_CODE_EXECUTION=true`
2. **Database**: Use SSL connections for PostgreSQL in production
3. **API Keys**: Never commit `.env` files to Git
4. **Nmap Permissions**: Ensure the application has proper permissions to run Nmap

---

## 📊 Verification

Test each component:

```bash
# 1. Check Nmap installation
nmap --version

# 2. Test database connection
cd Backend
python -c "from db import db; import asyncio; asyncio.run(db.connect()); print('✅ DB Connected')"

# 3. Check Redis
redis-cli ping  # Should return "PONG"

# 4. Test E2B (if configured)
python -c "from e2b_code_interpreter import Sandbox; print('✅ E2B SDK Installed')"
```

---

## 🆘 Troubleshooting

### Nmap not found
- Verify installation: `which nmap` or `where nmap`
- Check PATH includes the Nmap installation directory

### Prisma errors
- Run `prisma generate` after schema changes
- Ensure DATABASE_URL is correctly formatted

### E2B fallback mode
- Check E2B_API_KEY is set correctly
- Verify API key validity at e2b.dev dashboard

### Celery worker not starting
- Ensure Redis is running: `redis-cli ping`
- Check REDIS_URL in .env matches your Redis configuration
