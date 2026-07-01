# IGA-Guard 2.0 全栈启动（分步，避免卡住）
# 注意：train_bert 会从 HuggingFace 下载模型，可能耗时 5~30 分钟，默认跳过
param(
    [switch]$WithBert,   # 加 -WithBert 才训练 TinyBERT
    [switch]$SkipWeb     # 加 -SkipWeb 只跑数据/训练/评估
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $Root "..")
$env:PYTHONPATH = "src"

Write-Host "=== IGA-Guard 2.0 启动 ===" -ForegroundColor Cyan

Write-Host "[1/5] 生成数据集..." -ForegroundColor Yellow
python scripts/generate_dataset.py --variants 8

Write-Host "[2/5] 训练融合模型（约 5~15 秒）..." -ForegroundColor Yellow
python scripts/train.py --data data/samples/obfuscated_dataset.csv

if ($WithBert) {
    Write-Host "[3/5] TinyBERT 训练（可能很慢，需下载模型）..." -ForegroundColor Red
    python scripts/train_bert.py --epochs 2
} else {
    Write-Host "[3/5] 跳过 TinyBERT（使用 -WithBert 启用）" -ForegroundColor DarkGray
}

Write-Host "[4/5] 快速评估..." -ForegroundColor Yellow
python scripts/eval_explainability.py
python scripts/benchmark_latency.py --iterations 50 --warmup 20

if (-not $SkipWeb) {
    Write-Host "[5/5] 启动 Web（新窗口）..." -ForegroundColor Yellow
    $port = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue
    if ($port) {
        Write-Host "5000 端口已占用" -ForegroundColor Yellow
    } else {
        Start-Process python -ArgumentList "run.py" -WorkingDirectory $PWD
    }
    Write-Host "http://127.0.0.1:5000/" -ForegroundColor Green
}

Write-Host "=== 完成 ===" -ForegroundColor Green
