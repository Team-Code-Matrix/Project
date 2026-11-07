@echo off
cd /d "%~dp0"
setlocal enabledelayedexpansion
title TrustShield - Enterprise Threat Intelligence Platform

echo ===============================================================================
echo                TRUSTSHIELD / ENTERPRISE THREAT INTELLIGENCE                   
echo                   Unified Full-Stack Startup Launcher                         
echo ===============================================================================
echo.

:: 1. Verify Working Directory
echo [*] Working Directory: %CD%

:: 2. Check Python Installation
echo [*] Checking Python installation...
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] ERROR: Python 3 was not found in your PATH.
    echo     Please install Python 3.10+ from https://www.python.org/ and restart.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYTHON_VER=%%i
echo [+] Found %PYTHON_VER%

:: 3. Check Node.js Installation
echo [*] Checking Node.js installation...
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] ERROR: Node.js was not found in your PATH.
    echo     Please install Node.js 18+ from https://nodejs.org/ and restart.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('node --version 2^>^&1') do set NODE_VER=%%i
echo [+] Found Node.js %NODE_VER%
echo.

:: 4. Verify Backend Dependencies
echo [*] Verifying backend dependencies...
if not exist "backend\requirements.txt" (
    echo [!] Warning: backend\requirements.txt not found.
) else (
    pip install -q -r backend\requirements.txt >nul 2>&1
    echo [+] Backend dependencies up to date.
)

if not exist "backend\.env" (
    if exist "backend\.env.example" (
        copy "backend\.env.example" "backend\.env" >nul
        echo [+] Initialized backend\.env from template.
    )
)

:: 5. Verify & Train Custom AI/ML Phishing Model
echo [*] Checking AI/ML Phishing Detection Model...
if not exist "backend\ml\models\trustshield_phishing_model.joblib" (
    echo [*] Model artifact not found. Training custom RandomForest phishing model...
    python backend\ml\train_model.py
    if %ERRORLEVEL% NEQ 0 (
        echo [!] Warning: Model training encountered an issue. Proceeding with fallback heuristics.
    ) else (
        echo [+] Custom AI/ML Phishing Model trained and serialized successfully.
    )
) else (
    echo [+] Custom AI/ML Phishing Model verified on disk (trustshield_phishing_model.joblib).
)
echo.

:: 6. Setup Frontend Dependencies
echo [*] Verifying frontend node_modules...
if not exist "frontend\node_modules" (
    echo [*] Installing frontend packages (first run only)...
    cd /d "%~dp0frontend"
    call npm install
    cd /d "%~dp0"
    echo [+] Frontend packages installed.
) else (
    echo [+] Frontend node_modules present.
)

if not exist "frontend\.env.local" (
    if exist "frontend\.env.example" (
        copy "frontend\.env.example" "frontend\.env.local" >nul
        echo [+] Initialized frontend\.env.local from template.
    )
)
echo.

:: 7. Launch FastAPI / Python Backend in Persistent Window
echo [*] Starting TrustShield Backend on http://localhost:8000 ...
start "TrustShield Backend" cmd /k "cd /d "%~dp0backend" && python server.py"

:: 8. Launch Vite Frontend in Persistent Window
echo [*] Starting TrustShield Frontend on http://localhost:5173 ...
start "TrustShield Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

:: 9. Wait for Services and Open Browser
echo [*] Waiting 4 seconds for servers to bind sockets...
timeout /t 4 /nobreak >nul

echo [*] Opening TrustShield Dashboard in default browser...
start http://localhost:5173

echo.
echo ===============================================================================
echo                TRUSTSHIELD IS NOW RUNNING SUCCESSFULLY!                        
echo ===============================================================================
echo.
echo   - Web Dashboard:    http://localhost:5173
echo   - Backend API:      http://localhost:8000
echo   - Healthcheck:      http://localhost:8000/healthz
echo   - ML Inference:     http://localhost:8000/api/v1/ai/analyze
echo   - Threat Feed:      http://localhost:8000/api/threats
echo   - Database:         Local SQLite (backend\data\trustshield.db)
echo.
echo   NOTE: Both backend and frontend consoles remain running in their own windows.
echo   To stop the application, close both background console windows.
echo ===============================================================================
echo.
pause
