@echo off
:: LateralShield + TrapWeave — Windows Quick Start (No Docker)
:: Usage: Double-click start.bat or run from cmd

echo.
echo  LateralShield + TrapWeave — VisionX 2026 (Local Mode)
echo  ==========================================
echo.

:: Copy env
if not exist .env (
    copy .env.example .env
    echo [OK] Created .env
)

:: Start services
echo.
echo [1/2] Starting Backend API (Local Python)...
start "LateralShield Backend" cmd /k "cd backend && .\venv\Scripts\python.exe app.py"

echo.
echo [2/2] Starting Frontend Dashboard (Local Node)...
start "LateralShield Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo ==========================================
echo  LateralShield is running!
echo ==========================================
echo.
echo  Dashboard:    http://localhost:3000
echo  Backend API:  http://localhost:5000/api/health
echo.
echo  Close the newly opened command windows to stop.
echo.
pause
