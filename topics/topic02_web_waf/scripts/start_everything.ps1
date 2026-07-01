# IGA-Guard 2.0 全量启动脚本
# 用法: powershell -ExecutionPolicy Bypass -File scripts\start_everything.ps1
# 日志目录: logs/
# 说明: 慢任务（10k数据集、TinyBERT）在独立窗口运行，不阻塞主流程

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $Root "..")
$env:PYTHONPATH = "src"

$LogDir = Join-Path $PWD "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$ts = Get-Date -Format "yyyyMMdd_HHmmss"

function Start-LoggedProcess {
    param(
        [string]$Name,
        [string]$PythonArgs,
        [string]$LogFile
    )
    $logPath = Join-Path $LogDir $LogFile
    Write-Host "[START] $Name -> $logPath" -ForegroundColor Cyan
    Start-Process python -ArgumentList $PythonArgs -WorkingDirectory $PWD `
        -RedirectStandardOutput $logPath -RedirectStandardError "${logPath}.err" `
        -WindowStyle Minimized
}

Write-Host "========================================" -ForegroundColor Green
Write-Host " IGA-Guard 2.0 全量服务启动" -ForegroundColor Green
Write-Host " 日志: $LogDir" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# --- 同步：依赖与基础数据 ---
Write-Host "`n[同步] pip install..." -ForegroundColor Yellow
pip install -r requirements.txt 2>&1 | Tee-Object -FilePath (Join-Path $LogDir "pip_install.log")

Write-Host "[同步] 生成 10k 混淆数据集（可能 1~3 分钟）..." -ForegroundColor Yellow
python scripts/generate_dataset.py --variants 10 --count 10000 --seed 42 `
    2>&1 | Tee-Object -FilePath (Join-Path $LogDir "generate_10k.log")

Write-Host "[同步] 训练融合模型 RF..." -ForegroundColor Yellow
python scripts/train.py --data data/samples/obfuscated_10k.csv `
    2>&1 | Tee-Object -FilePath (Join-Path $LogDir "train_rf.log")

# --- 并行后台进程 ---
Start-LoggedProcess -Name "TinyBERT训练" `
    -PythonArgs "scripts/train_bert.py --data data/samples/obfuscated_10k.csv --epochs 3" `
    -LogFile "train_bert_$ts.log"

Start-LoggedProcess -Name "对抗演化实验" `
    -PythonArgs "scripts/run_adversarial.py --rounds 5 --data data/samples/obfuscated_10k.csv" `
    -LogFile "adversarial_$ts.log"

Start-LoggedProcess -Name "Flask-Web大屏" `
    -PythonArgs "run.py" `
    -LogFile "web_server_$ts.log"

Start-Sleep -Seconds 3

# --- 同步评估（使用已训练模型）---
Write-Host "`n[同步] 运行评估脚本..." -ForegroundColor Yellow
python scripts/evaluate.py --data data/samples/obfuscated_10k.csv `
    2>&1 | Tee-Object -FilePath (Join-Path $LogDir "evaluate.log")
python scripts/eval_explainability.py `
    2>&1 | Tee-Object -FilePath (Join-Path $LogDir "explainability.log")
python scripts/benchmark_latency.py --iterations 1000 --warmup 200 `
    2>&1 | Tee-Object -FilePath (Join-Path $LogDir "latency.log")

# --- 健康检查 ---
Write-Host "`n[检查] API 健康..." -ForegroundColor Yellow
try {
    $h = Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/health" -TimeoutSec 8
    Write-Host "  API: $($h.status) v$($h.version) engine=$($h.engine)" -ForegroundColor Green
} catch {
    Write-Host "  API 尚未就绪，请查看 logs/web_server_*.log" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host " 已启动进程:" -ForegroundColor Green
Write-Host "  1. Web 大屏     http://127.0.0.1:5000/" -ForegroundColor White
Write-Host "  2. TinyBERT训练 logs/train_bert_*.log" -ForegroundColor White
Write-Host "  3. 对抗实验     logs/adversarial_*.log" -ForegroundColor White
Write-Host "  4. 评估结果     results/ + logs/*.log" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Green
