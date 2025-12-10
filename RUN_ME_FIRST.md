# 🚀 Vaptiq.ai Quick Start Guide

## Prerequisites

Before starting, ensure you have installed:
- ✅ **Python 3.8+** - [Download](https://www.python.org/downloads/)
- ✅ **Node.js 18+** - [Download](https://nodejs.org/)
- ✅ **Git** - [Download](https://git-scm.com/)

---

## 🎯 Quick Start (Fastest Way)

### Step 1: Setup Environment File

```bash
# Navigate to Backend directory
cd Backend

# Copy the example env file
copy .env.example .env

# The app will now run in MOCK MODE (no API keys needed for testing)
```

### Step 2: Start Redis (Required for Celery)

**Option A: Using Docker (Recommended)**
```bash
docker run -d -p 6379:6379 --name vaptiq-redis redis:alpine
```

**Option B: Install Redis Locally**
- Windows: Download from [redis.io](https://redis.io/download) or use WSL
- Mac: `brew install redis && brew services start redis`
- Linux: `sudo apt-get install redis-server && sudo systemctl start redis`

###Step 3: Run the Application

**Method 1: One-Click Startup (Windows)**
```bash
# From project root
START_ALL.bat
```

This will open 3 windows:
- 🟢 Backend API Server (Port 8000)
- 🔵 Frontend Dashboard (Port 3000)
- 🟡 Celery Worker (Background tasks)

**Method 2: Manual Startup (All Platforms)**

```bash
# Terminal 1: Backend API
cd Backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2: Celery Worker
cd Backend
celery -A tasks worker --loglevel=info --pool=solo

# Terminal 3: Frontend
cd Frontend
npm install
npm run dev
```

---

## 🌐 Access Points

Once all services are running:

| Service | URL | Description |
|---------|-----|-------------|
| 🎨 Frontend Dashboard | http://localhost:3000 | Main UI |
| 📡 Backend API Docs | http://localhost:8000/docs | Swagger UI |
| 🔧 Backend Health | http://localhost:8000 | API status |

---

## ✅ Verification Steps

1. **Check Redis is running:**
   ```bash
   redis-cli ping
   # Should return: PONG
   ```

2. **Check Backend is running:**
   - Open http://localhost:8000/docs
   - You should see Swagger UI with all endpoints

3. **Check Frontend is running:**
   - Open http://localhost:3000
   - You should see the Vaptiq.ai dashboard

4. **Test a scan (optional):**
   - Click "New Scan" in the dashboard
   - Enter a target (e.g., `scanme.nmap.org`)
   - Watch the real-time logs

---

## 🔧 Troubleshooting

### ❌ "Port already in use"

```bash
# Windows: Find and kill process
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux/Mac: Find and kill process
lsof -ti:8000 | xargs kill -9
```

### ❌ "Redis connection refused"

```bash
# Check if Redis is running
redis-cli ping

# If not running, start it:
docker start vaptiq-redis
# OR
brew services start redis  # Mac
sudo systemctl start redis  # Linux
```

### ❌ "Module not found" errors

```bash
# Backend
cd Backend
pip install -r requirements.txt

# Frontend
cd Frontend
npm install
```

### ❌ "Nmap not found"

The app will still work, but scans will return a configuration error. To enable real scanning:

```bash
# Windows: Download from https://nmap.org/download.html
# Mac:
brew install nmap

# Linux:
sudo apt-get install nmap
```

---

## 🎓 Understanding Mock Mode

By default, the app runs in **MOCK MODE** which means:

- ✅ **Scans work** - Returns simulated vulnerabilities
- ✅ **No API keys needed** - LLM verification uses mock responses
- ✅ **Safe for testing** - No real network scans
- ✅ **Fast** - No external API calls

### Enabling Production Mode

To enable real scanning and AI verification, edit `Backend/.env`:

```bash
# 1. Get E2B API key from https://e2b.dev
E2B_API_KEY=e2b_your_actual_key

# 2. Get LLM API key (choose one)
LLM_PROVIDER=GEMINI
GEMINI_API_KEY=your_gemini_key

# 3. Install Nmap
# See troubleshooting section above
```

---

## 📊 Project Structure

```
Vaptiq.ai/
├── Backend/          # Python FastAPI + Celery
│   ├── main.py       # API endpoints
│   ├── agent.py      # Security scanning tools
│   ├── tasks.py      # Celery background tasks
│   └── .env          # Configuration (create from .env.example)
├── Frontend/         # Next.js 14 Dashboard
│   ├── app/          # Pages and components
│   └── package.json  # Dependencies
└── START_ALL.bat     # One-click startup script
```

---

## 🐳 Docker Deployment (Alternative)

For production deployment:

```bash
# Build and start all services
docker-compose up --build

# Access:
# Frontend: http://localhost:3000
# Backend: http://localhost:8000
```

---

## 🆘 Need Help?

If you're stuck:

1. Check the logs in the terminal windows
2. Verify all prerequisites are installed
3. Ensure Redis is running (`redis-cli ping`)
4. Review `Backend/SETUP_GUIDE.md` for detailed configuration

---

## 🎉 You're Ready!

Open http://localhost:3000 and start your first security scan!
