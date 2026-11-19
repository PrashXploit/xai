@echo off
echo ============================================
echo  XAI-Sec v2.0 - Launcher
echo ============================================
echo.

echo [1/2] Starting FastAPI backend on http://localhost:8000 ...
start "XAI-Sec Backend" cmd /k "cd /d %~dp0 && .\venv\Scripts\activate && uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload"

ping 127.0.0.1 -n 4 >nul

echo [2/2] Starting Next.js frontend on http://localhost:3000 ...
start "XAI-Sec Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ============================================
echo  Both servers started!
echo  Frontend: http://localhost:3000
echo  Backend:  http://localhost:8000
echo  API Docs: http://localhost:8000/docs
echo ============================================
