<#
.SYNOPSIS
    Convenient one-click launcher for the DPI/IDS/IPS Full-Stack System (FastAPI Backend + React SOC Frontend).
.DESCRIPTION
    Starts the FastAPI server on http://127.0.0.1:8000 and the Vite frontend on http://127.0.0.1:5173 in separate PowerShell windows.
#>

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " DPI/IDS/IPS SOC Full-Stack Launch Script" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Start Backend in separate window
Write-Host "[1/2] Launching FastAPI Backend on port 8000..." -ForegroundColor Yellow
$BackendCmd = "cd `"$Root\project_networking`"; `$env:PYTHONPATH=`"$Root\project_networking`"; `"$Root\.venv\Scripts\python.exe`" -m uvicorn backend.api.main:create_app --factory --host 127.0.0.1 --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $BackendCmd

# 2. Start Frontend in separate window
Write-Host "[2/2] Launching React Vite SOC Frontend on port 5173..." -ForegroundColor Yellow
$FrontendCmd = "cd `"$Root\frontend`"; npm run dev"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $FrontendCmd

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Both services initiated!" -ForegroundColor Green
Write-Host " Backend API:   http://127.0.0.1:8000/api/v1/health" -ForegroundColor White
Write-Host " WebSocket:     ws://127.0.0.1:8000/ws/monitor" -ForegroundColor White
Write-Host " SOC Dashboard: http://127.0.0.1:5173" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan

