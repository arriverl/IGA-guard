# IGA-Guard 2.0 快速启动（不训练、不下载模型，约 10 秒内完成）
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $Root "..")
$env:PYTHONPATH = "src"

Write-Host "=== IGA-Guard 快速启动 ===" -ForegroundColor Cyan

# 仅当模型不存在时才训练（秒级）
if (-not (Test-Path "models/fusion_detector.joblib")) {
    Write-Host "[*] 首次运行：生成数据并训练轻量模型..." -ForegroundColor Yellow
    python scripts/generate_dataset.py --variants 5
    python scripts/train.py --data data/samples/obfuscated_dataset.csv
}

Write-Host "[*] 健康检查..." -ForegroundColor Yellow
python scripts/detect.py --url "http://demo/login?id=1+union+select+1,2--" 2>&1 | Select-Object -First 5

Write-Host "[*] 启动 Web 服务（新窗口）..." -ForegroundColor Yellow
$already = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue
if ($already) {
    Write-Host "端口 5000 已占用，跳过启动。直接访问 http://127.0.0.1:5000/" -ForegroundColor Green
} else {
    Start-Process python -ArgumentList "run.py" -WorkingDirectory $PWD -WindowStyle Normal
    Start-Sleep -Seconds 2
    Write-Host "大屏: http://127.0.0.1:5000/" -ForegroundColor Green
}

Write-Host "完成。文献见 research/agent1_literature/  方案见 research/agent2_integration/" -ForegroundColor Cyan
