# Vaptiq.ai - Quick Start Guide

## 🚀 Starting the Application

### Method 1: One-Click Startup (Recommended)
Double-click `START_ALL.bat` in the root directory. This will:
- Install all dependencies
- Start both backend and frontend in separate windows
- Display startup progress

### Method 2: Python Direct Launcher (Most Reliable)
```bash
# Backend
cd apps/engine
python direct_start.py

# Frontend (in a new terminal)
cd apps/web
npm run dev
```

### Method 3: Individual Batch Files
```bash
# Backend
cd apps/engine
install_and_start.bat

# Frontend (in a new terminal)
cd apps/web
install_and_start.bat
```

## 🌐 Access Points

Once started, access the application at:
- **Frontend**: http://localhost:3000
- **Backend API Docs**: http://localhost:8000/docs
- **Backend Health**: http://localhost:8000

## ✅ Verification Checklist

1. ✓ Backend server shows "Uvicorn running on http://0.0.0.0:8000"
2. ✓ Frontend shows "Ready in X ms"
3. ✓ Navigate to http://localhost:3000 - Dashboard loads
4. ✓ Navigate to http://localhost:8000/docs - Swagger UI loads

## 🔧 Troubleshooting

### Port Already in Use
```bash
# Check what's using the ports
netstat -ano | findstr :8000
netstat -ano | findstr :3000

# Kill the process (replace PID with actual process ID)
taskkill /PID <PID> /F
```

### Dependencies Missing
```bash
# Backend
cd apps/engine
pip install -r requirements.txt

# Frontend
cd apps/web
npm install
```

### Python/Node Not Found
- Install Python 3.8+: https://www.python.org/downloads/
- Install Node.js 18+: https://nodejs.org/

## 📋 Core Features to Test

1. **Scanning**: Start a new scan from the dashboard
2. **History**: View previous scan logs
3. **Reports**: Generate PDF/HTML/JSON reports
4. **Attack Paths**: Visualize MITRE ATT&CK simulation
5. **Verification**: Test the AI-powered verification agent

## 🛠️ Development

- Backend uses FastAPI with auto-reload
- Frontend uses Next.js 14 with hot reload
- Changes to code will auto-refresh (except `.env` changes)

## 📝 Environment Variables

Create `.env` files if needed:

`apps/engine/.env`:
```env
OPENAI_API_KEY=your_key_here  # Optional, works in mock mode without
GEMINI_API_KEY=your_key_here  # Optional
MOONSHOT_API_KEY=your_key_here  # Optional
LLM_PROVIDER=OPENAI  # or GEMINI or KIMI
```

`apps/web/.env.local`:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```
