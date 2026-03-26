@echo off
:: LateralShield + TrapWeave — Windows Quick Start
:: Usage: Double-click start.bat or run from cmd

echo.
echo  LateralShield + TrapWeave — VisionX 2026
echo  ==========================================
echo.

:: Check Docker
where docker >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Docker not found. Install Docker Desktop from https://docker.com
    pause
    exit /b 1
)
echo [OK] Docker found

:: Copy env
if not exist .env (
    copy .env.example .env
    echo [OK] Created .env
)

:: Train models
echo.
echo [1/3] Training ML models (approx 2 minutes)...
docker compose --profile training run --rm trainer
echo [OK] Models trained

:: Start services
echo.
echo [2/3] Starting all services...
docker compose up -d
echo [OK] Services started

:: Wait for backend
echo.
echo [3/3] Waiting for backend...
timeout /t 15 /nobreak >nul

echo.
echo ==========================================
echo  LateralShield is running!
echo ==========================================
echo.
echo  Dashboard:    http://localhost:3000
echo  Backend API:  http://localhost:5000/api/health
echo  MongoDB:      localhost:27017
echo  Honeypot 1:   localhost:8445
echo  Honeypot 2:   localhost:8433
echo.
echo  To stop: docker compose down
echo.
pause
